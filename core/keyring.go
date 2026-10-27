package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
)

// SecretStore is the OS keyring. Values are tokens or Red-SecretsXAI ciphertext.
// Plaintext private keys are never stored here.
type SecretStore interface {
	Put(account string, secret []byte) error
	Get(account string) ([]byte, error)
	Delete(account string) error
}

const keyringService = "RottenCore"

// MemoryKeyring keeps secrets in this process. Tests use it so nothing is written
// to a keychain or a file.
type MemoryKeyring struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *MemoryKeyring) Put(account string, secret []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string][]byte{}
	}
	s.m[account] = append([]byte(nil), secret...)
	return nil
}

func (s *MemoryKeyring) Get(account string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.m[account]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}

func (s *MemoryKeyring) Delete(account string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, account)
	return nil
}

// OSKeyring talks to the operating system secret store.
// Linux: secret-tool (stdin). macOS: Security.framework via python (stdin).
// Windows: DPAPI ciphertext under the support folder, never the plaintext.
type OSKeyring struct {
	Dir string // Windows DPAPI blob directory; unused on Linux and macOS
}

func (k OSKeyring) Put(account string, secret []byte) error {
	var err error
	switch runtime.GOOS {
	case "darwin":
		_, err = darwinKeychain(account, secret, "put")
	case "windows":
		_, err = windowsDPAPI(k.dir(), account, secret, "put")
	default:
		_, err = secretTool(account, secret, "put")
	}
	return err
}

func (k OSKeyring) Get(account string) ([]byte, error) {
	switch runtime.GOOS {
	case "darwin":
		return darwinKeychain(account, nil, "get")
	case "windows":
		return windowsDPAPI(k.dir(), account, nil, "get")
	default:
		return secretTool(account, nil, "get")
	}
}

func (k OSKeyring) Delete(account string) error {
	switch runtime.GOOS {
	case "darwin":
		_, err := darwinKeychain(account, nil, "del")
		return err
	case "windows":
		_, err := windowsDPAPI(k.dir(), account, nil, "del")
		return err
	default:
		_, err := secretTool(account, nil, "del")
		return err
	}
}

func (k OSKeyring) dir() string {
	if k.Dir != "" {
		return k.Dir
	}
	return SupportDir()
}

func (c *Core) secrets() SecretStore {
	if c != nil && c.Secrets != nil {
		return c.Secrets
	}
	dir := ""
	if c != nil && c.State != nil {
		dir = c.State.Dir
	}
	return OSKeyring{Dir: dir}
}

// AccessToken returns ROTTENCORE_ACCESS_TOKEN or the keyring copy.
// The token is not logged. A missing keyring entry is ErrSignInRequired.
func (c *Core) AccessToken() (string, error) {
	if v := os.Getenv("ROTTENCORE_ACCESS_TOKEN"); v != "" {
		return v, nil
	}
	b, err := c.secrets().Get("access-token")
	if err != nil || len(b) == 0 {
		return "", ErrSignInRequired
	}
	return string(b), nil
}

func secretToolArgs(op, account string) []string {
	switch op {
	case "put":
		return []string{"store", "--label=RottenCore", "service", keyringService, "account", account}
	case "get":
		return []string{"lookup", "service", keyringService, "account", account}
	default:
		return []string{"clear", "service", keyringService, "account", account}
	}
}

func secretTool(account string, secret []byte, op string) ([]byte, error) {
	bin, err := exec.LookPath("secret-tool")
	if err != nil {
		return nil, errors.New("OS keyring is not available (secret-tool); refusing to store this in a file")
	}
	cmd := exec.Command(bin, secretToolArgs(op, account)...)
	if op == "put" {
		cmd.Stdin = bytes.NewReader(secret)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if op == "get" {
			return nil, os.ErrNotExist
		}
		if len(secret) > 0 && (bytes.Contains(stderr.Bytes(), secret) || bytes.Contains(stdout.Bytes(), secret)) {
			return nil, errors.New("OS keyring failed")
		}
		return nil, fmt.Errorf("OS keyring failed: %w", err)
	}
	if op == "get" {
		return append([]byte(nil), bytes.TrimRight(stdout.Bytes(), "\n")...), nil
	}
	return nil, nil
}

// darwinKeychain uses Security.framework. The secret is a stdin frame, not an argument.
func darwinKeychain(account string, secret []byte, op string) ([]byte, error) {
	py, err := exec.LookPath("python3")
	if err != nil {
		return nil, errors.New("OS keyring needs python3 on macOS; refusing to store this in a file")
	}
	var frame bytes.Buffer
	writeFrame := func(b []byte) {
		var n [4]byte
		n[0] = byte(len(b) >> 24)
		n[1] = byte(len(b) >> 16)
		n[2] = byte(len(b) >> 8)
		n[3] = byte(len(b))
		frame.Write(n[:])
		frame.Write(b)
	}
	writeFrame([]byte(op))
	writeFrame([]byte(keyringService))
	writeFrame([]byte(account))
	if op == "put" {
		writeFrame(secret)
	}
	cmd := exec.Command(py, "-c", darwinKeychainScript)
	cmd.Stdin = &frame
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if op == "get" {
			return nil, os.ErrNotExist
		}
		if bytes.Contains(stderr.Bytes(), secret) {
			return nil, errors.New("OS keyring failed")
		}
		return nil, errors.New("OS keyring failed")
	}
	if op == "get" {
		return append([]byte(nil), stdout.Bytes()...), nil
	}
	return nil, nil
}

const darwinKeychainScript = `
import ctypes, sys
def frame():
    nraw = sys.stdin.buffer.read(4)
    if len(nraw) != 4:
        raise SystemExit(2)
    n = int.from_bytes(nraw, "big")
    b = sys.stdin.buffer.read(n)
    if len(b) != n:
        raise SystemExit(2)
    return b
op = frame().decode()
service = frame()
account = frame()
sec = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/Security.framework/Security")
sec.SecKeychainAddGenericPassword.restype = ctypes.c_int32
sec.SecKeychainFindGenericPassword.restype = ctypes.c_int32
sec.SecKeychainItemDelete.restype = ctypes.c_int32
sec.SecKeychainItemFreeContent.restype = ctypes.c_int32
if op == "del" or op == "put":
    item = ctypes.c_void_p()
    st = sec.SecKeychainFindGenericPassword(None, len(service), service, len(account), account, None, None, ctypes.byref(item))
    if st == 0 and item:
        sec.SecKeychainItemDelete(item)
if op == "put":
    secret = frame()
    st = sec.SecKeychainAddGenericPassword(None, len(service), service, len(account), account, len(secret), secret, None)
    if st != 0:
        raise SystemExit(1)
elif op == "get":
    ln = ctypes.c_uint32()
    data = ctypes.c_void_p()
    st = sec.SecKeychainFindGenericPassword(None, len(service), service, len(account), account, ctypes.byref(ln), ctypes.byref(data), None)
    if st != 0 or not data:
        raise SystemExit(1)
    buf = ctypes.string_at(data, ln.value)
    sec.SecKeychainItemFreeContent(None, data)
    sys.stdout.buffer.write(buf)
`

func windowsDPAPI(dir, account string, secret []byte, op string) ([]byte, error) {
	sum := sha256.Sum256([]byte(account))
	name := hex.EncodeToString(sum[:])
	path := filepath.Join(dir, "keyring", name+".dpapi")
	if op == "del" {
		err := os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	ps, err := exec.LookPath("powershell")
	if err != nil {
		return nil, errors.New("OS keyring needs PowerShell DPAPI; refusing to store this in a file")
	}
	if op == "get" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", windowsUnprotect)
		cmd.Stdin = bytes.NewReader(b)
		out, err := cmd.Output()
		if err != nil {
			return nil, errors.New("OS keyring failed")
		}
		return base64.StdEncoding.DecodeString(string(bytes.TrimSpace(out)))
	}
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", windowsProtect)
	cmd.Stdin = bytes.NewReader([]byte(base64.StdEncoding.EncodeToString(secret)))
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New("OS keyring failed")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return nil, os.WriteFile(path, bytes.TrimSpace(out), 0o600)
}

const windowsProtect = `Add-Type -AssemblyName System.Security
$b = [Convert]::FromBase64String([Console]::In.ReadToEnd())
$p = [System.Security.Cryptography.ProtectedData]::Protect($b, $null, 'CurrentUser')
[Console]::Out.Write([Convert]::ToBase64String($p))
`

const windowsUnprotect = `Add-Type -AssemblyName System.Security
$b = [Convert]::FromBase64String([Console]::In.ReadToEnd())
$p = [System.Security.Cryptography.ProtectedData]::Unprotect($b, $null, 'CurrentUser')
[Console]::Out.Write([Convert]::ToBase64String($p))
`
