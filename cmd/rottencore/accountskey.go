package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/grimvirusoffical-source/RottenCore/core"
	"github.com/grimvirusoffical-source/RottenCore/devhub"
	"github.com/grimvirusoffical-source/RottenCore/seal"
)

// The Red-XAI Accounts full-access key (final design): read ONLY from a hidden prompt on the controlling
// terminal, at pairing and at signing time. Never stored (no Keychain item), never in env, argv, a file,
// logs or output. Held in a []byte that is zeroed after use. net/http needs one string copy per request
// header; that copy cannot be zeroed and lives only in this process.

// accountsKeyEnvRe matches environment variable NAMES that look like an Accounts key. Any match refuses to
// run, so the key can never ride in from the environment.
var accountsKeyEnvRe = regexp.MustCompile(`(?i)ACCOUNTS?.*(KEY|TOKEN|SECRET)|^(REDX|RED_XAI|RXA)_.*(KEY|TOKEN|SECRET)`)

// refuseAccountsKeyEnv returns an error naming (not printing the value of) any matching variable.
func refuseAccountsKeyEnv(environ []string) error {
	var bad []string
	for _, kv := range environ {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if accountsKeyEnvRe.MatchString(name) {
			bad = append(bad, name)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("refusing to run: %s is set; the Red-XAI Accounts key is typed at the prompt only (unset it)", strings.Join(bad, ", "))
	}
	return nil
}

// ttyOpen opens the controlling terminal; a var so tests can use a pipe.
var ttyOpen = func() (io.ReadWriteCloser, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("no controlling terminal: run this in Terminal on the Mac (the Accounts key is typed at a hidden prompt)")
	}
	return f, nil
}

// ttyEcho turns terminal echo on/off for the tty; a var so tests can stub it.
var ttyEcho = func(tty io.ReadWriteCloser, on bool) error {
	f, ok := tty.(*os.File)
	if !ok {
		return nil
	}
	arg := "-echo"
	if on {
		arg = "echo"
	}
	cmd := exec.Command("/bin/stty", arg)
	cmd.Stdin = f
	return cmd.Run()
}

// zero overwrites a secret buffer.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// readTTYLine reads one line byte-by-byte (no bufio copy) into a fixed buffer. The caller zeroes it.
func readTTYLine(r io.Reader, max int) ([]byte, error) {
	buf := make([]byte, 0, max)
	one := make([]byte, 1)
	for {
		n, err := r.Read(one)
		if n == 1 {
			if one[0] == '\n' || one[0] == '\r' {
				break
			}
			if len(buf) == max {
				zero(buf[:cap(buf)])
				return nil, errors.New("input too long")
			}
			buf = append(buf, one[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			zero(buf[:cap(buf)])
			return nil, err
		}
	}
	one[0] = 0
	return buf, nil
}

// readAccountsKey prompts on the tty with echo off and returns the key bytes (zero them after use).
func readAccountsKey() ([]byte, error) {
	if err := refuseAccountsKeyEnv(os.Environ()); err != nil {
		return nil, err
	}
	tty, err := ttyOpen()
	if err != nil {
		return nil, err
	}
	defer tty.Close()
	fmt.Fprint(tty, "Red-XAI Accounts full-access key (input hidden, not stored): ")
	if err := ttyEcho(tty, false); err != nil {
		return nil, fmt.Errorf("cannot hide input: %w", err)
	}
	k, rerr := readTTYLine(tty, 4096)
	_ = ttyEcho(tty, true)
	fmt.Fprintln(tty)
	if rerr != nil {
		return nil, rerr
	}
	t := bytes.TrimSpace(k)
	if len(t) == 0 {
		zero(k)
		return nil, errors.New("no Red-XAI Accounts key entered")
	}
	out := make([]byte, len(t))
	copy(out, t)
	zero(k[:cap(k)])
	return out, nil
}

// confirmAccount prints the server-returned identity and requires Josh to type exactly "yes" on the tty.
func confirmAccount(who *devhub.AccountIdentity, what string) error {
	tty, err := ttyOpen()
	if err != nil {
		return err
	}
	defer tty.Close()
	fmt.Fprintf(tty, "\nra-core resolved the Accounts key to:\n  name:    %s\n  email:   %s\n  subject: %s\n", who.Name, who.Email, string(who.Subject))
	fmt.Fprintf(tty, "Type yes to %s with this identity: ", what)
	line, err := readTTYLine(tty, 16)
	if err != nil {
		return err
	}
	if string(line) != "yes" {
		return errors.New("not confirmed (type exactly yes)")
	}
	return nil
}

// checkServerSubject is the loose sanity check on the server's subject plus the optional exact cross-check
// with the ids Josh exported (ROTTEN_DEV_ID / ROTTEN_TEAM_ID).
func checkServerSubject(who *devhub.AccountIdentity, wantDev, wantTeam string) error {
	if who == nil || len(bytes.TrimSpace(who.Subject)) == 0 {
		return errors.New("ra-core returned no account subject (PENDING API shape)")
	}
	s, _, err := core.SanityCheckSubject(who.Subject)
	if err != nil {
		return fmt.Errorf("ra-core subject failed the id sanity check: %w", err)
	}
	dev, team := core.SubjectIDs(s)
	if wantDev != "" && dev != wantDev {
		return fmt.Errorf("ra-core subject devId %q != ROTTEN_DEV_ID %q (exact)", dev, wantDev)
	}
	if wantTeam != "" && team != wantTeam {
		return fmt.Errorf("ra-core subject teamId %q != ROTTEN_TEAM_ID %q (exact)", team, wantTeam)
	}
	return nil
}

// signingIdentityCheck runs before sign-batch touches the Mega key.
func signingIdentityCheck(ctx context.Context) error {
	if strings.TrimSpace(trustRootHex) == "" {
		return errors.New("sign-batch needs --trust-root <ceremony root public key hex>")
	}
	applySigningDefaults()
	if signBundle == "" {
		return errors.New("sign-batch needs --bundle")
	}
	leafJSON, chain, err := readBundleLeaf(signBundle)
	if err != nil {
		return err
	}
	if _, err := core.VerifyCertChain(chain, chainPolicy()); err != nil {
		return fmt.Errorf("the Mega bundle does not verify to the ceremony root: %w", err)
	}
	if err := refuseAccountsKeyEnv(os.Environ()); err != nil {
		return err
	}
	base := devhubURL()
	if base == "" {
		base = "https://api.rottenapplestore.org"
	}
	akey, err := readAccountsKey()
	if err != nil {
		return err
	}
	defer zero(akey)
	c := &devhub.Client{BaseURL: base, Platform: devhub.PlatformMac, AccountsKey: akey}
	who, err := c.AccountStatus(ctx)
	c.AccountsKey = nil
	zero(akey)
	if err != nil {
		return fmt.Errorf("ra-core account status: %w", err)
	}
	if err := checkServerSubject(who, os.Getenv("ROTTEN_DEV_ID"), os.Getenv("ROTTEN_TEAM_ID")); err != nil {
		return err
	}
	if err := core.EqualSubjectBytes(leafJSON, who.Subject); err != nil {
		return fmt.Errorf("Mega bundle vs ra-core: %w", err)
	}
	return confirmAccount(who, "sign the release assets")
}

// readBundleLeaf returns the bundle's leaf exactly as stored plus the parsed chain.
func readBundleLeaf(path string) ([]byte, []core.Cert, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	plain, err := seal.Current().Open(seal.CertBundle, bytes.TrimSpace(b), nil)
	if err != nil {
		return nil, nil, err
	}
	var raw struct {
		Chain []json.RawMessage `json:"chain"`
	}
	if err := json.Unmarshal(plain, &raw); err != nil || len(raw.Chain) == 0 {
		return nil, nil, fmt.Errorf("%s: no certificate chain", path)
	}
	chain := make([]core.Cert, len(raw.Chain))
	for i, c := range raw.Chain {
		if err := json.Unmarshal(c, &chain[i]); err != nil {
			return nil, nil, fmt.Errorf("%s: certificate %d: %w", path, i, err)
		}
	}
	return raw.Chain[0], chain, nil
}
