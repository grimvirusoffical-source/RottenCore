package sign

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"strings"
)

// Sealer seals and opens Red-SecretsXAI ciphertext. Encrypt and Decrypt must not log
// password or plaintext. The shared module can supply its own Sealer later.
type Sealer interface {
	Encrypt(ctx context.Context, password, plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ctx context.Context, password, ciphertext []byte) (plaintext []byte, err error)
}

// RedSecretsXAI calls red-xai-encrypt (encrypt_text / decrypt_text, password mode).
// It does not implement the cipher. Password and plaintext are passed on stdin, never
// as arguments, and they are not kept in the child's environment.
type RedSecretsXAI struct{}

// redSecretsScript is the whole call. It imports redxai and prints only a type name on failure.
const redSecretsScript = `
import sys
from redxai import encrypt_text, decrypt_text

def frame():
    nraw = sys.stdin.buffer.read(4)
    if len(nraw) != 4:
        raise SystemExit(2)
    n = int.from_bytes(nraw, "big")
    if n > 8000000:
        raise SystemExit(2)
    b = sys.stdin.buffer.read(n)
    if len(b) != n:
        raise SystemExit(2)
    return b

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("enc", "dec"):
        raise SystemExit(2)
    pw = frame().decode("utf-8")
    data = frame()
    try:
        if sys.argv[1] == "enc":
            tok = encrypt_text(data.decode("utf-8"), pw, mode="password")
            sys.stdout.write(tok)
        else:
            text = decrypt_text(data.decode("utf-8"), pw, mode="password")
            sys.stdout.write(text)
        sys.stdout.flush()
    except Exception as e:
        sys.stderr.write("RSXERR %s\n" % type(e).__name__)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
`

func (RedSecretsXAI) Encrypt(ctx context.Context, password, plaintext []byte) ([]byte, error) {
	return callRedSecrets(ctx, "enc", password, plaintext)
}

func (RedSecretsXAI) Decrypt(ctx context.Context, password, ciphertext []byte) ([]byte, error) {
	return callRedSecrets(ctx, "dec", password, ciphertext)
}

func callRedSecrets(ctx context.Context, op string, password, payload []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("the Red-SecretsXAI password was empty")
	}
	if len(password) > 4096 || len(payload) == 0 || len(payload) > 8_000_000 {
		return nil, errors.New("Red-SecretsXAI refused the input size")
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		return nil, errors.New("Red-SecretsXAI needs python3 with red-xai-encrypt installed")
	}
	frame := framePair(password, payload)
	defer Wipe(frame)
	cmd := exec.CommandContext(ctx, py, "-c", redSecretsScript, op)
	cmd.Env = sealedEnv()
	cmd.Stdin = bytes.NewReader(frame)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if runErr != nil {
		leaked := bytes.Contains(stderr.Bytes(), password) || bytes.Contains(stdout.Bytes(), password) || bytes.Contains(stderr.Bytes(), payload)
		msg := stderr.String()
		switch {
		case leaked:
			return nil, errors.New("Red-SecretsXAI failed")
		case strings.Contains(msg, "ModuleNotFoundError"):
			return nil, errors.New("Red-SecretsXAI is not installed (pip install red-xai-encrypt)")
		case strings.Contains(msg, "WrongPasswordError"):
			return nil, errors.New("Red-SecretsXAI did not accept the password")
		default:
			return nil, errors.New("Red-SecretsXAI failed")
		}
	}
	out := append([]byte(nil), stdout.Bytes()...)
	if len(out) == 0 {
		return nil, errors.New("Red-SecretsXAI returned nothing")
	}
	return out, nil
}

func framePair(a, b []byte) []byte {
	var buf bytes.Buffer
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(a)))
	buf.Write(n[:])
	buf.Write(a)
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	buf.Write(n[:])
	buf.Write(b)
	return buf.Bytes()
}

func sealedEnv() []string {
	var out []string
	for _, k := range []string{"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "RSX_LIB"} {
		if v, ok := os.LookupEnv(k); ok {
			out = append(out, k+"="+v)
		}
	}
	return out
}
