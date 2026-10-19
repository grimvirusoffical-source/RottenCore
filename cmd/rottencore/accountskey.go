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
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/grimvirusoffical-source/RottenCore/core"
	"github.com/grimvirusoffical-source/RottenCore/devhub"
	"github.com/grimvirusoffical-source/RottenCore/seal"
)

// The Red-XAI Accounts key (ra-core-issued, ra_sk_live_<43 base62>; Dev page → API keys → Red-XAI
// Accounts key): read ONLY from a hidden prompt on the controlling terminal, at pairing and at signing time,
// and format-checked before use. Never stored (no Keychain item), never in env, argv, a file,
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

// promptSignals subscribes the hidden prompt to the abort signals; a var so tests can inject one.
var promptSignals = func(c chan<- os.Signal) { signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP) }

// promptInterrupted ends the process after an abort at the hidden prompt (echo already restored).
var promptInterrupted = func() {
	fail(errors.New("interrupted at the Red-XAI Accounts key prompt: nothing was sent or stored"), 130)
}

// readTTYLine reads one line byte-by-byte (no bufio copy) into a fixed buffer. The caller zeroes it.
func readTTYLine(r io.Reader, max int) ([]byte, error) {
	return readTTYLineInto(r, make([]byte, 0, max))
}

// readTTYLineInto is readTTYLine into a caller-owned buffer (len 0), so an abort can zero it.
func readTTYLineInto(r io.Reader, buf []byte) ([]byte, error) {
	max := cap(buf)
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
	fmt.Fprint(tty, "Red-XAI Accounts key (ra_sk_live_…, Dev page > API keys > Red-XAI Accounts key; input hidden, not stored): ")
	if err := ttyEcho(tty, false); err != nil {
		return nil, fmt.Errorf("cannot hide input: %w", err)
	}
	// QA L4: Ctrl-C (or SIGTERM/SIGHUP) at the hidden prompt aborts at once: echo back on, partial input
	// zeroed, exit 130. Without this the main NotifyContext swallowed SIGINT and the read kept blocking.
	buf := make([]byte, 0, 4096)
	sig := make(chan os.Signal, 1)
	promptSignals(sig)
	done := make(chan struct{})
	go func() {
		select {
		case <-sig:
			zero(buf[:cap(buf)])
			_ = ttyEcho(tty, true)
			fmt.Fprintln(tty)
			promptInterrupted()
		case <-done:
		}
	}()
	k, rerr := readTTYLineInto(tty, buf)
	close(done)
	signal.Stop(sig)
	_ = ttyEcho(tty, true)
	fmt.Fprintln(tty)
	if rerr != nil {
		return nil, rerr
	}
	t := bytes.TrimSpace(k)
	if len(t) == 0 {
		zero(k[:cap(k)])
		return nil, errors.New("no Red-XAI Accounts key entered")
	}
	if err := core.ValidateAccountsKeyFormat(t); err != nil { // the error never contains the key
		zero(k[:cap(k)])
		return nil, err
	}
	out := make([]byte, len(t))
	copy(out, t)
	zero(k[:cap(k)])
	return out, nil
}

// validateAccountStatus applies the ra-core contract to an account-status answer and returns the exact
// subject bytes (cert.subject) the Mega certificate must carry. Stops on: account.subject null, cert not
// ready, contexts not exactly one, or any disagreement between account.subject, cert and contexts[0].
func validateAccountStatus(st *devhub.AccountStatusResponse) ([]byte, error) {
	if st == nil {
		return nil, errors.New("STOP: ra-core sent an empty answer to GET /v1/devhub/account-status. Nothing was signed; try again later or tell QA")
	}
	a := &st.Account
	if !a.RxaLinked || a.Sub == "" {
		return nil, errors.New("STOP: your ra-core account is not linked to Red-XAI Accounts yet. Verify your email in Red-XAI Accounts first, then get the account linked (the link matches that verified email), and run this again")
	}
	if !a.HasSubject() {
		return nil, errors.New("STOP: ra-core has no certificate subject for your account yet, so no Mega cert can be issued. Make sure your email is verified and the account is linked to Red-XAI Accounts, then run this again")
	}
	if !st.Cert.Ready || st.Cert.Subject == "" {
		return nil, errors.New("STOP: ra-core says your certificate ids are not ready yet (your Red-XAI id or team id is missing). Verify your email in Red-XAI Accounts and get the account linked, then run this again")
	}
	if len(st.Contexts) != 1 {
		return nil, fmt.Errorf("STOP: this Accounts key belongs to %d developer contexts (teams); signing needs exactly one. Use the key of the account that owns the one team you are signing for", len(st.Contexts))
	}
	want := []byte(st.Cert.Subject)
	if !bytes.Equal(bytes.TrimSpace(a.Subject), want) {
		return nil, fmt.Errorf("STOP: ra-core gave two different subjects for your account (%s vs %s). Nothing was signed; tell QA", a.Subject, want)
	}
	var sub core.CertSubject
	if err := json.Unmarshal(want, &sub); err != nil {
		return nil, fmt.Errorf("STOP: ra-core's certificate subject is not {name,teamId,devId}: %w. Nothing was signed; tell QA", err)
	}
	dev, team := core.SubjectIDs(sub)
	kind, err := core.ValidateIDPair(dev, team)
	if err != nil {
		return nil, fmt.Errorf("STOP: ra-core's certificate subject has an invalid id (%w). Nothing was signed; tell QA", err)
	}
	c := st.Contexts[0]
	switch {
	case dev != a.Sub || dev != st.Cert.DevID:
		return nil, fmt.Errorf("STOP: ra-core's developer ids disagree (subject devId %q, account %q, cert %q). Nothing was signed; tell QA", dev, a.Sub, st.Cert.DevID)
	case team != st.Cert.TeamID || team != c.CertTeamID:
		return nil, fmt.Errorf("STOP: ra-core's team ids disagree (subject teamId %q, cert %q, team %q). Nothing was signed; tell QA", team, st.Cert.TeamID, c.CertTeamID)
	case sub.Name != c.Name:
		return nil, fmt.Errorf("STOP: the certificate name %q is not the team name %q ra-core reports. Nothing was signed; tell QA", sub.Name, c.Name)
	case (kind == core.TeamIndividual) != (c.Kind == "individual"):
		return nil, fmt.Errorf("STOP: ra-core says this is a %q context but the team id is %q (an individual uses your rxa_ id, a team an rxt_ id). Nothing was signed; tell QA", c.Kind, team)
	}
	return want, nil
}

// crossCheckIDs is the OPTIONAL exact check against ROTTEN_DEV_ID / ROTTEN_TEAM_ID (empty = skipped).
func crossCheckIDs(subject []byte, wantDev, wantTeam string) error {
	if err := core.ValidateCrossCheckIDs(wantDev, wantTeam); err != nil {
		return err
	}
	var sub core.CertSubject
	if err := json.Unmarshal(subject, &sub); err != nil {
		return err
	}
	dev, team := core.SubjectIDs(sub)
	if wantDev != "" && dev != wantDev {
		return fmt.Errorf("optional cross-check failed: ra-core subject devId %q != %q", dev, wantDev)
	}
	if wantTeam != "" && team != wantTeam {
		return fmt.Errorf("optional cross-check failed: ra-core subject teamId %q != %q", team, wantTeam)
	}
	return nil
}

// confirmAccount prints the server-returned identity and requires Josh to type exactly "yes" on the tty.
func confirmAccount(st *devhub.AccountStatusResponse, what string) error {
	tty, err := ttyOpen()
	if err != nil {
		return err
	}
	defer tty.Close()
	c := devhub.AccountContext{}
	if len(st.Contexts) == 1 {
		c = st.Contexts[0]
	}
	fmt.Fprintf(tty, "\nra-core resolved the Red-XAI Accounts key to:\n  name:    %s\n  email:   %s\n  sub:     %s\n  context: %s %q (role %s, mega %v)\n  subject: %s\n",
		st.Account.Name, st.Account.Email, st.Account.Sub, c.Kind, c.Name, c.Role, c.Mega, st.Cert.Subject)
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

// explainHubError turns the contract's 4xx codes into clear, final (non-retrying) errors.
func explainHubError(err error) error {
	switch {
	case err == nil:
		return nil
	case devhub.IsAccountsKeyMismatch(err):
		return fmt.Errorf("STOP: the Red-XAI Accounts key and the build API key belong to different ra-core accounts (403 accounts_key_mismatch). Not retrying. Use both keys from the same account")
	case devhub.IsPairingAccountMismatch(err):
		return fmt.Errorf("STOP: this pairing was started with another account's Red-XAI Accounts key (403 pairing_account_mismatch). Approve it while signed in as the key's account, or start again")
	case devhub.IsAccountsKeyRequired(err):
		return fmt.Errorf("STOP: ra-core did not accept that Red-XAI Accounts key (401 accounts_key_required). Create a new one on the Dev page under API keys > Red-XAI Accounts key and paste it at the prompt")
	case devhub.IsRxaLinkRequired(err):
		return fmt.Errorf("STOP: your ra-core account is not linked to Red-XAI Accounts (409 rxa_link_required). Verify your email in Red-XAI Accounts first, then get the account linked, and run this again")
	}
	return err
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
	c := &devhub.Client{BaseURL: base, AllowLoopbackHTTP: testLoopbackHTTP, Platform: devhub.PlatformMac, AccountsKey: akey}
	st, err := c.AccountStatus(ctx)
	c.AccountsKey = nil
	zero(akey)
	if err != nil {
		return fmt.Errorf("ra-core account status: %w", explainHubError(err))
	}
	subject, err := validateAccountStatus(st)
	if err != nil {
		return err
	}
	// OPTIONAL cross-check (identity comes from ra-core + Josh's yes); fails closed on mismatch.
	xDev, xTeam := os.Getenv("ROTTEN_DEV_ID"), os.Getenv("ROTTEN_TEAM_ID")
	if xDev != "" || xTeam != "" {
		fmt.Fprintln(os.Stderr, "optional cross-check: ROTTEN_DEV_ID/ROTTEN_TEAM_ID must match ra-core's subject exactly")
	}
	if err := crossCheckIDs(subject, xDev, xTeam); err != nil {
		return err
	}
	if err := core.EqualSubjectBytes(leafJSON, subject); err != nil {
		return fmt.Errorf("Mega bundle vs ra-core: %w", err)
	}
	return confirmAccount(st, "sign the release assets")
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
