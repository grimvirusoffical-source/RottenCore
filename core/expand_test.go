package core

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestQuickLoginRemembersOnlyWhenAsked(t *testing.T) {
	var hits []string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		switch r.URL.Path {
		case "/redxai-connect/start":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"device_code": "devcode", "user_code": "AB12CD34",
				"verification_uri": srv.URL + "/redxai-connectx#request=opaque",
				"expires_in":       60, "interval": 1, "protocol": QuickLoginProtocol,
			})
		case "/redxai-connect/token":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"protocol": QuickLoginProtocol, "token_type": "Bearer",
				"access_token": "rxca_test", "refresh_token": "rxcr_test",
				"expires_in": 3600, "remember_device": false,
				"user": map[string]interface{}{"sub": "acct", "email": "dev@example.com", "email_verified": true},
			})
		case "/redxai-connect/userinfo":
			if r.Header.Get("Authorization") != "Bearer rxca_test" {
				http.Error(w, "no", 401)
				return
			}
			w.WriteHeader(200)
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(Discovery{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/oauth2/authorize", TokenEndpoint: srv.URL + "/oauth2/token",
				UserinfoEndpoint: srv.URL + "/oauth2/userinfo", JWKSURI: srv.URL + "/oauth2/jwks"})
		case "/oauth2/userinfo":
			json.NewEncoder(w).Encode(map[string]interface{}{"sub": "acct", "email": "dev@example.com", "email_verified": true})
		case "/v1/rxa-account":
			json.NewEncoder(w).Encode(map[string]interface{}{"idVerified": false})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := testCore(t, newFake(), "", nil)
	c.Net.AllowLoopbackHTTP = true
	mem := &MemoryKeyring{}
	c.Secrets = mem
	c.Accounts = &OIDCAccounts{Issuer: srv.URL, Net: c.Net}
	var opened string
	who, err := c.LoginQuick(context.Background(), func(p LoginPrompt) { opened = p.VerificationURI })
	if err != nil {
		t.Fatal(err)
	}
	if who.Email != "dev@example.com" || opened == "" || strings.Contains(opened, "rxca_test") {
		t.Fatalf("%+v %s", who, opened)
	}
	if _, err := mem.Get("access-token"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("remember_device false stored a token")
	}
	filepath.Walk(c.State.Dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(path)
		if strings.Contains(string(b), "rxca_test") || strings.Contains(string(b), "rxcr_test") {
			t.Fatalf("token landed in %s", path)
		}
		return nil
	})
	if !strings.Contains(strings.Join(hits, " "), "/redxai-connect/userinfo") {
		t.Fatalf("userinfo not called: %v", hits)
	}
}

func TestDeveloperSignAndOpen(t *testing.T) {
	c, _, _, dev, _, password, seed, seal := lifetimeFixture(t)
	mem := &MemoryKeyring{}
	c.Secrets = mem
	launcher := filepath.Join(t.TempDir(), "ra-launcher")
	if err := os.Symlink("/bin/sleep", launcher); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ROTTENCORE_RA_LAUNCHER", launcher)
	cmd := exec.Command(launcher, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, inst, run := LauncherStatus(); inst && run {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	dir := t.TempDir()
	app := makeApp(t, dir, "Tool", "com.acme.tool", "1.2.0", `{"schema":1,"appId":"com.acme.tool","name":"Tool","version":"1.2.0","source":"store"}`)
	zip := filepath.Join(dir, "tool.zip")
	zipApp(t, app, zip)
	res, err := c.SignDeveloper(context.Background(), dev, []byte(password), zip, "linux", seal)
	if err != nil {
		t.Fatal(err)
	}
	if !res.LauncherRequired || res.CertID == "" {
		t.Fatalf("%+v", res)
	}
	raw, _ := os.ReadFile(res.Output)
	pub, _ := os.ReadFile(c.devCertPath())
	if strings.Contains(string(raw), seed) || strings.Contains(string(pub), seed) || strings.Contains(string(raw), password) {
		t.Fatal("secret in carrier or registry")
	}
	ct, err := mem.Get("dev-priv:dev@example.com")
	if err != nil || strings.Contains(string(ct), seed) {
		t.Fatal("keyring should hold ciphertext, not the seed")
	}
	if _, err := c.OpenSigned(context.Background(), zip, []byte("nope"), true, seal); err == nil {
		t.Fatal("wrong password installed")
	}
	if _, err := os.Stat(filepath.Join(c.Engine.Applications, "Tool.app")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed open still installed")
	}
	ent, err := c.OpenSigned(context.Background(), zip, []byte(password), true, seal)
	if err != nil {
		t.Fatal(err)
	}
	if ent.AppID != "com.acme.tool" || ent.Version != "1.2.0" {
		t.Fatalf("%+v", ent)
	}
	if _, err := c.OpenSigned(context.Background(), filepath.Join(dir, "not-ours.txt"), []byte(password), true, seal); !errors.Is(err, ErrNotOurs) {
		t.Fatal(err)
	}
}

func TestDaemonQueuesCarriersAndResets(t *testing.T) {
	c := testCore(t, newFake(), "", nil)
	if err := os.MkdirAll(c.State.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(c.State.Dir, "installed.json"), []byte("{}\n"), 0o600)
	dl := t.TempDir()
	os.WriteFile(filepath.Join(dl, "App.zip.Red_SecretXAI"), []byte("RXAI2.not-a-key"), 0o600)
	err := c.RunDaemon(context.Background(), DaemonConfig{
		Tick:      time.Hour,
		Stall:     time.Hour,
		MaxUptime: time.Minute,
		RSSLimit:  1 << 40,
		Downloads: dl,
		Started:   time.Now().Add(-time.Hour),
	})
	if !errors.Is(err, ErrDaemonReset) || !strings.Contains(err.Error(), "uptime") {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(c.State.Dir, "pending-imports.json"))
	if err != nil || !strings.Contains(string(b), "App.zip.Red_SecretXAI") {
		t.Fatalf("%s %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(c.State.Dir, "installed.json")); err != nil {
		t.Fatal("reset removed user data")
	}
}

func TestAutostartHasNoSecrets(t *testing.T) {
	path, data, err := AutostartPlan("darwin", "/Users/me", "/usr/local/bin/rottencore")
	if err != nil || !strings.Contains(path, "LaunchAgents") || !strings.Contains(string(data), "/usr/local/bin/rottencore") {
		t.Fatalf("%s %s %v", path, data, err)
	}
	if strings.Contains(string(data), "private") || strings.Contains(string(data), "password") {
		t.Fatal(string(data))
	}
	path, data, err = AutostartPlan("linux", "/home/me", "/usr/local/bin/rottencore")
	if err != nil || !strings.HasSuffix(path, "rottencore.service") || !strings.Contains(string(data), "MemoryMax=128M") {
		t.Fatalf("%s %s %v", path, data, err)
	}
}

func TestDaemonResetReasons(t *testing.T) {
	if daemonResetReason(80<<20, 64<<20, time.Minute, time.Hour, time.Second, time.Minute) != "memory" {
		t.Fatal("memory")
	}
	if daemonResetReason(1, 64<<20, 13*time.Hour, 12*time.Hour, time.Second, time.Minute) != "uptime" {
		t.Fatal("uptime")
	}
	if daemonResetReason(1, 64<<20, time.Minute, time.Hour, 4*time.Minute, 3*time.Minute) != "watchdog" {
		t.Fatal("watchdog")
	}
	if daemonResetReason(1, 64<<20, time.Minute, time.Hour, time.Second, time.Minute) != "" {
		t.Fatal("healthy")
	}
}

func TestKeyringSecretStaysOffArgv(t *testing.T) {
	dir := t.TempDir()
	// The helper the OS keyring actually execs. A fake earlier on PATH records
	// argv and stdin and exits 0, so this never talks to a real keychain.
	name := "secret-tool"
	switch runtime.GOOS {
	case "darwin":
		name = "python3"
	case "windows":
		name = "powershell"
	}
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$0.argv\"\ncat > \"$0.stdin\"\nprintf '%s\\n' 'ZHVtbXk='\n"
	bin := filepath.Join(dir, name)
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	const secret = "kr-sentinel-44"
	kr := OSKeyring{Dir: dir}
	if err := kr.Put("access-token", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	argv, err := os.ReadFile(bin + ".argv")
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := os.ReadFile(bin + ".stdin")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(argv), secret) {
		t.Fatalf("secret on argv: %s", argv)
	}
	switch runtime.GOOS {
	case "darwin":
		if !strings.Contains(string(stdin), secret) {
			t.Fatal("darwin keychain stdin dropped the framed secret")
		}
	case "windows":
		if strings.Contains(string(stdin), secret) {
			t.Fatal("DPAPI stdin held the plaintext")
		}
		matches, _ := filepath.Glob(filepath.Join(dir, "keyring", "*.dpapi"))
		if len(matches) == 0 {
			t.Fatal("DPAPI put wrote no ciphertext file")
		}
		for _, p := range matches {
			b, _ := os.ReadFile(p)
			if strings.Contains(string(b), secret) {
				t.Fatal("DPAPI file held the plaintext")
			}
		}
	default:
		if string(stdin) != secret {
			t.Fatalf("stdin %q", stdin)
		}
	}
}
