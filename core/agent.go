package core

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/internal/sign"
)

// The signing agent holds the unlocked lifetime key and the Red-SecretsXAI password
// in memory for one login. It listens on a 0600 socket in the support folder.
// Requests are refused when they carry anything other than the fields below, and
// nothing the agent prints includes the key or the password.

const (
	agentMaxToken = 16 << 10
	agentMaxPass  = 4096
	agentMaxLine  = 1 << 20
)

// ReadAgentHandshake reads the app's unlock frames: a big-endian length and bytes
// for the access token, then the same for the Red-SecretsXAI password.
func ReadAgentHandshake(r io.Reader) (token string, password []byte, err error) {
	tb, err := readFrame(r, agentMaxToken)
	if err != nil {
		return "", nil, err
	}
	password, err = readFrame(r, agentMaxPass)
	if err != nil {
		sign.Wipe(tb)
		return "", nil, err
	}
	if len(tb) == 0 || len(password) == 0 {
		sign.Wipe(tb)
		sign.Wipe(password)
		return "", nil, errors.New("the signing agent needs an account token and a Red-SecretsXAI password")
	}
	token = string(tb)
	sign.Wipe(tb)
	return token, password, nil
}

func readFrame(r io.Reader, max int) ([]byte, error) {
	var nbuf [4]byte
	if _, err := io.ReadFull(r, nbuf[:]); err != nil {
		return nil, errors.New("the signing agent handshake was closed")
	}
	n := int(binary.BigEndian.Uint32(nbuf[:]))
	if n < 0 || n > max {
		return nil, errors.New("the signing agent handshake was rejected")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		sign.Wipe(buf)
		return nil, errors.New("the signing agent handshake was closed")
	}
	return buf, nil
}

// agentSocket is {support}/sign-agent.sock when that path fits in a unix address.
// Darwin allows 104 bytes including the trailing NUL, and a test temp dir on macOS
// is longer than that, so the socket then lives at a short private path under /tmp.
func (c *Core) agentSocket() (string, error) {
	if c == nil || c.State == nil || c.State.Dir == "" {
		return "", errors.New("RottenCore has no support folder")
	}
	preferred := filepath.Join(c.State.Dir, "sign-agent.sock")
	if unixSocketFits(preferred) {
		return preferred, nil
	}
	sum := sha256.Sum256([]byte(preferred))
	return filepath.Join("/tmp", "rc-"+hex.EncodeToString(sum[:8]), "s"), nil
}

func unixSocketFits(path string) bool {
	// sun_path includes a trailing NUL: 104 bytes on Darwin, 108 on Linux.
	max := 107
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		max = 103
	}
	return len(path) <= max
}

func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0o077 != 0 {
		return errors.New("the signing agent socket directory is not private")
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if ok && int(sys.Uid) != os.Getuid() {
		return errors.New("the signing agent socket directory is not private")
	}
	return nil
}

type agentRequest struct {
	Op           string `json:"op"`
	Token        string `json:"token,omitempty"`
	Path         string `json:"path,omitempty"`
	Platform     string `json:"platform,omitempty"`
	WithLauncher bool   `json:"withLauncher"`
}

type agentEnvelope struct {
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// RunAgent unlocks the lifetime cert for this process and serves the local socket
// until the context is cancelled or the app sends shutdown. The key and password
// are wiped before it returns.
func (c *Core) RunAgent(ctx context.Context, token string, password []byte, sealer sign.Sealer) error {
	pw := append([]byte(nil), password...)
	defer sign.Wipe(pw)
	_, cert, role, err := c.loadAccount(ctx, token)
	if err != nil {
		return err
	}
	if role != sign.RoleOwner {
		return ErrNotOwnerUnlock
	}
	if cert.PrivateEnc == "" || cert.Kind != sign.CertKind {
		return ErrKeyWithheld
	}
	key, err := unlockKey(ctx, sealerOr(sealer), pw, cert)
	if err != nil {
		return err
	}
	defer sign.Wipe(key)
	held := LifetimeCert{
		Kind: cert.Kind, CertID: cert.CertID, PubKey: cert.PubKey, Issued: cert.Issued,
		OwnerEmails: append([]string(nil), cert.OwnerEmails...), SigIDPrefix: cert.SigIDPrefix,
	}
	ln, err := c.listenAgent()
	if err != nil {
		return err
	}
	var once sync.Once
	stop := func() { once.Do(func() { ln.Close() }) }
	go func() {
		<-ctx.Done()
		stop()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil
		}
		if c.serveAgent(ctx, conn, key, &held, pw, sealerOr(sealer)) {
			stop()
			return nil
		}
	}
}

func (c *Core) listenAgent() (net.Listener, error) {
	if c.State == nil || c.State.Dir == "" {
		return nil, errors.New("RottenCore has no support folder")
	}
	if c.AgentRunning() {
		return nil, errors.New("the signing agent is already running")
	}
	if err := os.MkdirAll(c.State.Dir, 0o700); err != nil {
		return nil, err
	}
	sock, err := c.agentSocket()
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateDir(filepath.Dir(sock)); err != nil {
		return nil, err
	}
	os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// serveAgent handles one connection. It reports whether the agent should exit.
func (c *Core) serveAgent(ctx context.Context, conn net.Conn, key ed25519.PrivateKey, cert *LifetimeCert, password []byte, sealer sign.Sealer) bool {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 4096), agentMaxLine)
	if !sc.Scan() {
		writeAgent(conn, false, "the signing agent refused the request", nil)
		return false
	}
	raw := append([]byte(nil), sc.Bytes()...)
	defer sign.Wipe(raw)
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	var req agentRequest
	if err := dec.Decode(&req); err != nil || dec.More() {
		writeAgent(conn, false, "the signing agent refused the request", nil)
		return false
	}
	switch req.Op {
	case "status":
		writeAgent(conn, true, "", map[string]bool{"running": true, "unlocked": true})
		return false
	case "shutdown":
		writeAgent(conn, true, "", map[string]bool{"stopped": true})
		return true
	case "sign":
		res, err := c.agentSign(ctx, req, key, cert, password, sealer)
		if err != nil {
			writeAgent(conn, false, safeAgentErr(err), nil)
			return false
		}
		writeAgent(conn, true, "", res)
		return false
	default:
		writeAgent(conn, false, "the signing agent refused the request", nil)
		return false
	}
}

func (c *Core) agentSign(ctx context.Context, req agentRequest, key ed25519.PrivateKey, cert *LifetimeCert, password []byte, sealer sign.Sealer) (*SignResult, error) {
	_, _, role, err := c.loadAccount(ctx, req.Token)
	if err != nil {
		return nil, err
	}
	_, installed, running := LauncherStatus()
	if err := sign.Allow(runtime.GOOS, req.Platform, role, req.WithLauncher, installed, running); err != nil {
		return nil, err
	}
	if req.Path == "" {
		return nil, errors.New("sign needs the file to sign")
	}
	return c.sealSigned(ctx, key, cert, req.Path, req.Platform, req.WithLauncher, sealer, password)
}

func safeAgentErr(err error) string {
	if err == nil {
		return ""
	}
	// These sentences are ours. Anything else stays generic so a wrapped
	// library error cannot carry key material back to the caller.
	switch {
	case errors.Is(err, ErrOwnerSession), errors.Is(err, ErrKeyWithheld), errors.Is(err, ErrAgentDown),
		errors.Is(err, ErrNotOwnerUnlock), errors.Is(err, ErrSignInRequired), errors.Is(err, sign.ErrDevLauncher),
		errors.Is(err, sign.ErrLauncherDown), errors.Is(err, ErrAccountsComingSoon):
		return err.Error()
	}
	msg := err.Error()
	switch msg {
	case "sign needs the file to sign", "platform must be macos, ios, android, windows or linux":
		return msg
	}
	if len(msg) < 160 && (stringsHas(msg, "cannot sign for") || stringsHas(msg, "not available on") || stringsHas(msg, "no rottencore.json") || stringsHas(msg, "rottencore.json")) {
		return msg
	}
	return "the signing agent could not sign that file"
}

func stringsHas(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func writeAgent(conn net.Conn, ok bool, err string, result interface{}) {
	var raw json.RawMessage
	if result != nil {
		b, jerr := json.Marshal(result)
		if jerr != nil {
			ok, err, raw = false, "the signing agent could not sign that file", nil
		} else {
			raw = b
		}
	}
	enc := json.NewEncoder(conn)
	_ = enc.Encode(agentEnvelope{OK: ok, Error: err, Result: raw})
}

func bytesReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct{ b []byte }

func (s *sliceReader) Read(p []byte) (int, error) {
	if len(s.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.b)
	s.b = s.b[n:]
	return n, nil
}

// AgentRunning reports whether a signing agent is answering on the local socket.
func (c *Core) AgentRunning() bool {
	if c == nil || c.State == nil || c.State.Dir == "" {
		return false
	}
	sock, err := c.agentSocket()
	if err != nil {
		return false
	}
	conn, err := net.DialTimeout("unix", sock, 200*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(conn, "{\"op\":\"status\"}\n"); err != nil {
		return false
	}
	var env agentEnvelope
	if err := json.NewDecoder(conn).Decode(&env); err != nil || !env.OK {
		return false
	}
	var st struct {
		Running bool `json:"running"`
	}
	if err := json.Unmarshal(env.Result, &st); err != nil {
		return false
	}
	return st.Running
}

// AgentSign asks the running agent to sign. The token is the caller's account, not a key.
func (c *Core) AgentSign(ctx context.Context, token, path, platform string, withLauncher bool) (*SignResult, error) {
	if !c.AgentRunning() {
		return nil, ErrAgentDown
	}
	sock, err := c.agentSocket()
	if err != nil {
		return nil, ErrAgentDown
	}
	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		return nil, ErrAgentDown
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	req := agentRequest{Op: "sign", Token: token, Path: path, Platform: platform, WithLauncher: withLauncher}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, ErrAgentDown
	}
	var env agentEnvelope
	if err := json.NewDecoder(conn).Decode(&env); err != nil {
		return nil, errors.New("the signing agent did not answer")
	}
	if !env.OK {
		if env.Error == "" {
			return nil, errors.New("the signing agent could not sign that file")
		}
		return nil, errors.New(env.Error)
	}
	var res SignResult
	if err := json.Unmarshal(env.Result, &res); err != nil || res.SigID == "" {
		return nil, errors.New("the signing agent did not answer")
	}
	return &res, nil
}

// ShutdownAgent tells the running agent to wipe the key and exit.
func (c *Core) ShutdownAgent(ctx context.Context) error {
	if c == nil || c.State == nil {
		return ErrAgentDown
	}
	sock, err := c.agentSocket()
	if err != nil {
		return ErrAgentDown
	}
	conn, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		return ErrAgentDown
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(conn).Encode(agentRequest{Op: "shutdown"}); err != nil {
		return ErrAgentDown
	}
	var env agentEnvelope
	if err := json.NewDecoder(conn).Decode(&env); err != nil || !env.OK {
		return errors.New("the signing agent did not stop")
	}
	return nil
}
