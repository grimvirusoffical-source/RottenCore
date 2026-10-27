package sign

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedSecretsXAIInvocationKeepsPasswordOffArgv(t *testing.T) {
	dir := t.TempDir()
	src := `package main
import (
  "encoding/base64"
  "encoding/binary"
  "io"
  "os"
)
func frame() []byte {
  var n [4]byte
  if _, err := io.ReadFull(os.Stdin, n[:]); err != nil { os.Exit(2) }
  ln := binary.BigEndian.Uint32(n[:])
  b := make([]byte, ln)
  if _, err := io.ReadFull(os.Stdin, b); err != nil { os.Exit(2) }
  return b
}
func main() {
  exe, _ := os.Executable()
  dir := exe[:stringsLast(exe)]
  os.WriteFile(dir+"/argv.txt", []byte(stringsJoin(os.Args, "\n")), 0600)
  pw := frame()
  data := frame()
  os.WriteFile(dir+"/pw.bin", pw, 0600)
  op := os.Args[len(os.Args)-1]
  if op == "enc" {
    os.Stdout.Write([]byte("RXAI2." + base64.StdEncoding.EncodeToString(data)))
    return
  }
  if op == "dec" {
    raw := data
    const p = "RXAI2."
    if len(raw) >= len(p) && string(raw[:len(p)]) == p {
      b, err := base64.StdEncoding.DecodeString(string(raw[len(p):]))
      if err != nil { os.Exit(1) }
      raw = b
    }
    os.Stdout.Write(raw)
    return
  }
  os.Exit(2)
}
func stringsLast(s string) int {
  for i := len(s) - 1; i >= 0; i-- {
    if s[i] == '/' || s[i] == '\\' { return i }
  }
  return 0
}
func stringsJoin(a []string, sep string) string {
  out := ""
  for i, s := range a {
    if i > 0 { out += sep }
    out += s
  }
  return out
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "python3")
	cmd := exec.Command("go", "build", "-o", bin, "main.go")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GO111MODULE=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper: %v %s", err, out)
	}
	t.Setenv("PATH", dir)
	const pw = "pw-sentinel-9f3a"
	const plain = "not-the-password"
	ct, err := (RedSecretsXAI{}).Encrypt(context.Background(), []byte(pw), []byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	argv, _ := os.ReadFile(filepath.Join(dir, "argv.txt"))
	if strings.Contains(string(argv), pw) || strings.Contains(string(argv), plain) {
		t.Fatalf("secret on argv: %s", argv)
	}
	gotPW, _ := os.ReadFile(filepath.Join(dir, "pw.bin"))
	if string(gotPW) != pw {
		t.Fatal("password did not arrive on stdin")
	}
	os.Remove(filepath.Join(dir, "argv.txt"))
	os.Remove(filepath.Join(dir, "pw.bin"))
	back, err := (RedSecretsXAI{}).Decrypt(context.Background(), []byte(pw), ct)
	if err != nil || string(back) != plain {
		t.Fatalf("%q %v", back, err)
	}
	Wipe(back)
}

func TestRedSecretsXAIRoundTrip(t *testing.T) {
	if exec.Command("python3", "-c", "import redxai").Run() != nil {
		t.Skip("red-xai-encrypt is not installed")
	}
	ctx := context.Background()
	const plain = "hello-secret"
	ct, err := (RedSecretsXAI{}).Encrypt(ctx, []byte("pw-1"), []byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(ct), "RXAI2.") {
		t.Fatalf("not a Red-SecretsXAI text token: %.12q", ct)
	}
	bad, err := (RedSecretsXAI{}).Decrypt(ctx, []byte("nope"), ct)
	if err == nil || strings.Contains(err.Error(), plain) || strings.Contains(err.Error(), "pw-1") || strings.Contains(err.Error(), "nope") {
		t.Fatalf("bad decrypt: %v %q", err, bad)
	}
	out, err := (RedSecretsXAI{}).Decrypt(ctx, []byte("pw-1"), ct)
	if err != nil || string(out) != plain {
		t.Fatalf("%q %v", out, err)
	}
	Wipe(out)
}
