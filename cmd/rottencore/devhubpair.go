package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/ca"
	"github.com/grimvirusoffical-source/RottenCore/core"
	"github.com/grimvirusoffical-source/RottenCore/devhub"
)

// devhub-pair flags.
var (
	pairDevID       string // OPTIONAL cross-check of ra-core's subject devId (ROTTEN_DEV_ID); never the identity source
	pairDeviceLabel string // Keychain label of the device key (default rottencore-device)
	pairName        string // device name shown in the dashboard
	pairState       string // pairing state file (code + poll secret, 0600)
	pairAPIKeyLabel string // Keychain account holding the build API key (default ra-build-api-key)
	pairKeyStdin    bool   // read the build API key from stdin instead of the Keychain
	pairTimeout     time.Duration
)

// pairKeychain is the store used for the device and Mega keys; a var so tests can swap it.
var pairKeychain interface {
	Has(label string) bool
	Put(label string, k core.Signer) error
	Get(label string) (core.Signer, error)
	GetSecret(label string) (string, error)
} = ca.KeychainStore{}

// runDevhubPair is `rottencore devhub-pair` (QA F1/M1): Phase 2 of the rollout entirely in Go.
//
//	rottencore devhub-pair --trust-root <hex> --out josh-mega.bundle.json --state work/pairing.json [--dev rxa_… --team …  (optional cross-check)]
//	    [--label josh-mega] [--device-label rottencore-device] [--name xlr1-mac] [--api-key-stdin]
//
// The Red-XAI Accounts key is typed at a hidden /dev/tty prompt (never stored, never env/argv)
// and sent to ra-core in devhub.AccountsKeyHeader on the pairing and cert requests. Before the cert is
// requested, the identity ra-core returns (name, email, subject) is shown and Josh must type "yes". The
// issued cert's subject must equal ra-core's subject byte for byte, be for our Mega key, and chain to the
// ceremony root (--trust-root is mandatory).
//
// The device and Mega Ed25519 keys are generated in this process and written straight into the login
// Keychain (security -i over stdin); the private keys never leave this process except into the Keychain.
// The build API key comes from the Keychain (account ra-build-api-key) or stdin; never argv or env.
func runDevhubPair(ctx context.Context) {
	// No hand-fed identity: who the cert is for comes only from the subject ra-core returns, which Josh
	// confirms by typing yes. --dev/--team are an OPTIONAL extra cross-check (fail closed on mismatch).
	if err := core.ValidateCrossCheckIDs(pairDevID, devTeam); err != nil {
		fail(err, 2)
	}
	if pairDevID != "" || devTeam != "" {
		fmt.Fprintln(os.Stderr, "optional cross-check: ra-core's subject must also match --dev/--team exactly (identity still comes from ra-core)")
	}
	if strings.TrimSpace(trustRootHex) == "" {
		fail(errors.New("devhub-pair needs --trust-root <ceremony root public key hex>: the issued chain must verify to it"), 2)
	}
	if err := refuseAccountsKeyEnv(os.Environ()); err != nil {
		fail(err, 2)
	}
	if buildOut == "" || pairState == "" {
		fail(errors.New("devhub-pair needs --out <bundle.json> and --state <pairing.json>"), 2)
	}
	if signLabel == "" {
		signLabel = "josh-mega"
	}
	if pairDeviceLabel == "" {
		pairDeviceLabel = "rottencore-device"
	}
	if signLabel == pairDeviceLabel {
		fail(errors.New("the Mega key and the device key must use different Keychain labels"), 2)
	}
	if pairName == "" {
		pairName = "xlr1-mac"
	}
	base := devhubURL()
	if base == "" {
		base = "https://api.rottenapplestore.org"
	}
	kc := pairKeychain
	if s, ok := kc.(ca.KeychainStore); ok && signService != "" {
		s.Service = signService
		kc = s
	}

	c := &devhub.Client{BaseURL: base, AllowLoopbackHTTP: testLoopbackHTTP, Platform: devhub.PlatformMac}
	info, err := c.CAChainInfo(ctx)
	check(err)
	if !info.Issuing {
		fail(errors.New("dev hub ca/chain reports issuing=false: load issuing.bundle.json on ra-core first"), 3)
	}

	key, err := readBuildKey(kc)
	check(err)
	c.APIKey = key
	akey, err := readAccountsKey()
	check(err)
	if bytes.Equal(akey, []byte(key)) {
		zero(akey)
		fail(errors.New("that is the build API key, not the Red-XAI Accounts key (Dev page: API keys > Red-XAI Accounts key)"), 2)
	}
	defer zero(akey)
	c.AccountsKey = akey
	onExit(func() { zero(akey) })

	fmt.Fprintln(os.Stderr, "Keychain: macOS will ask to let `security` read the keys. Click \"Allow\", NEVER \"Always Allow\".")
	dev, err := ensureKeychainKey(ctx, kc, pairDeviceLabel)
	check(err)
	mega, err := ensureKeychainKey(ctx, kc, signLabel)
	check(err)
	c.Device = dev
	fmt.Printf("DEVICE_FP=%s\nMEGA_KEY_FP=%s\n", devhub.Fingerprint(dev.Public()), devhub.Fingerprint(mega.Public()))

	timeout := pairTimeout
	if timeout <= 0 {
		timeout = 12 * time.Minute
	}
	st, err := pairAndWait(ctx, c, timeout)
	check(err)
	fmt.Printf("pairing approved: device=%s team=%s targets=%v\n", st.Device, st.Team, st.Targets)
	if err := writeJSON0600(pairState+".approved", st); err != nil {
		check(err)
	}

	chain, raw, subject, resp, err := issueMegaCert(ctx, c, mega, st, pairDevID, devTeam)
	zero(akey)
	c.AccountsKey = nil
	if err != nil {
		fail(err, 5)
	}
	if _, err := core.VerifyCertChain(chain, chainPolicy()); err != nil {
		fail(fmt.Errorf("issued chain does not verify to the ceremony root: %w", err), 5)
	}
	fmt.Println("chain verifies to the ceremony root")
	check(writeBundleExact(buildOut, raw))
	// Re-read what landed on disk: the stored leaf must still carry the exact subject bytes.
	stored, _, err := readBundleLeaf(buildOut)
	check(err)
	if err := core.EqualSubjectBytes(stored, subject); err != nil {
		fail(fmt.Errorf("bundle on disk lost the exact subject bytes: %w", err), 5)
	}
	leaf := chain[0]
	out(map[string]interface{}{"bundle": buildOut, "fingerprint": resp.Fingerprint, "subject": leaf.Subject, "platforms": leaf.Platforms},
		func() {
			fmt.Printf("cert subject %s (byte-for-byte equal to ra-core cert.subject) fingerprint=%s\n", subject, resp.Fingerprint)
			fmt.Printf("MEGA_BUNDLE=%s\n", buildOut)
		})
}

// issueMegaCert runs the contract steps after approval: the poll's account must be present (the pairing was
// started with the Accounts key) and agree with account-status; account-status must pass
// validateAccountStatus; optional ids cross-check; Josh types yes; then challenge + /certs (build key as
// Bearer + Accounts key) and the issued leaf must be a developer cert for our Mega key whose subject member
// equals cert.subject byte for byte.
func issueMegaCert(ctx context.Context, c *devhub.Client, mega devhub.DeviceKey, pst *devhub.PairingStatus, wantDev, wantTeam string) ([]core.Cert, []json.RawMessage, []byte, *devhub.CertResponse, error) {
	if pst.Account == nil || !pst.Account.HasSubject() {
		return nil, nil, nil, nil, errors.New("STOP: the approved pairing carries no account (it was not started with the Red-XAI Accounts key, or ra-core has no subject yet). Delete work/pairing.json and pair again")
	}
	st, err := c.AccountStatus(ctx)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("ra-core account status: %w", explainHubError(err))
	}
	subject, err := validateAccountStatus(st)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if pst.Account.ID != st.Account.ID || pst.Account.Sub != st.Account.Sub || !bytes.Equal(bytes.TrimSpace(pst.Account.Subject), subject) {
		return nil, nil, nil, nil, fmt.Errorf("STOP: the pairing was approved for %s %s but the Accounts key is %s %s", pst.Account.Sub, pst.Account.Subject, st.Account.Sub, subject)
	}
	if wantDev != "" || wantTeam != "" {
		fmt.Fprintln(os.Stderr, "optional cross-check: --dev/--team must match ra-core's subject exactly")
	}
	if err := crossCheckIDs(subject, wantDev, wantTeam); err != nil {
		return nil, nil, nil, nil, err
	}
	if err := confirmAccount(st, "issue the Mega signing certificate"); err != nil {
		return nil, nil, nil, nil, err
	}
	resp, err := c.IssueCert(ctx, mega)
	if err != nil {
		return nil, nil, nil, nil, explainHubError(err)
	}
	chain, raw, err := certChainFrom(resp)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err := checkMegaLeaf(&chain[0], raw[0], mega.Public(), subject); err != nil {
		return nil, nil, nil, nil, err
	}
	return chain, raw, subject, resp, nil
}

// writeBundleExact writes the bundle with the store's certificate bytes untouched (compact json.Marshal
// keeps RawMessage bytes as they are; MarshalIndent would re-indent the certificate and break the exact
// subject bytes).
func writeBundleExact(path string, raw []json.RawMessage) error {
	b, err := json.Marshal(struct {
		Chain []json.RawMessage `json:"chain"`
		Tier  string            `json:"tier"`
	}{raw, "developer"})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// readBuildKey loads the build API key from the Keychain or stdin. Never argv, never the environment.
func readBuildKey(kc interface{ GetSecret(string) (string, error) }) (string, error) {
	label := pairAPIKeyLabel
	if label == "" {
		label = "ra-build-api-key"
	}
	if !pairKeyStdin {
		if k, err := kc.GetSecret(label); err == nil && k != "" {
			fmt.Fprintf(os.Stderr, "build API key: from Keychain (%s)\n", label)
			return k, nil
		}
	}
	tty := isTerminal(os.Stdin)
	if tty {
		fmt.Fprint(os.Stderr, "Build API key (ra_sk_…, input hidden): ")
		_ = sttyEcho(false)
		defer func() { _ = sttyEcho(true); fmt.Fprintln(os.Stderr) }()
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	k := strings.TrimSpace(line)
	if k == "" {
		return "", fmt.Errorf("no build API key: store it in the Keychain as %s or pipe it on stdin", label)
	}
	return k, nil
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func sttyEcho(on bool) error {
	arg := "-echo"
	if on {
		arg = "echo"
	}
	cmd := exec.Command("/bin/stty", arg)
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

// ensureKeychainKey returns the Ed25519 key under label, generating it into the Keychain when absent.
// Existence is checked with an attribute-only lookup (no prompt); an existing item is never overwritten.
func ensureKeychainKey(ctx context.Context, kc interface {
	Has(string) bool
	Put(string, core.Signer) error
	Get(string) (core.Signer, error)
}, label string) (devhub.DeviceKey, error) {
	if !kc.Has(label) {
		k, _, err := ca.GenerateKey(ctx, &ca.Mixer{}, core.AlgEd25519, label)
		if err != nil {
			return nil, err
		}
		if err := kc.Put(label, k); err != nil {
			return nil, fmt.Errorf("store %s in the Keychain: %w", label, err)
		}
		fmt.Fprintf(os.Stderr, "generated %s in the Keychain\n", label)
	} else {
		fmt.Fprintf(os.Stderr, "%s already in the Keychain\n", label)
	}
	k, err := kc.Get(label)
	if err != nil {
		return nil, fmt.Errorf("read %s from the Keychain (click Allow): %w", label, err)
	}
	dk, ok := k.(devhub.DeviceKey)
	if !ok || k.Alg() != core.AlgEd25519 {
		return nil, fmt.Errorf("Keychain item %s is not an Ed25519 key", label)
	}
	return dk, nil
}

type pairState0 struct {
	devhub.Pairing
	Started int64 `json:"startedMs"`
}

// pairAndWait reuses a live pairing from the state file or starts one, prints the code, and polls until
// approved. Expired pairings are restarted (up to 3 codes). Denied is fatal. Nothing is marked approved
// until the store says approved (QA L4).
func pairAndWait(ctx context.Context, c *devhub.Client, timeout time.Duration) (*devhub.PairingStatus, error) {
	deadline := time.Now().Add(timeout)
	for attempt := 0; attempt < 3; attempt++ {
		var p *devhub.Pairing
		if b, err := os.ReadFile(pairState); err == nil {
			var s pairState0
			if json.Unmarshal(b, &s) == nil && s.Code != "" && s.ExpiresMs > time.Now().UnixMilli() {
				p = &s.Pairing
				fmt.Fprintln(os.Stderr, "resuming the pairing in", pairState)
			}
		}
		if p == nil {
			np, err := c.StartPairing(pairName)
			if err != nil {
				return nil, explainHubError(err)
			}
			p = np
			if err := writeJSON0600(pairState, pairState0{Pairing: *p, Started: time.Now().UnixMilli()}); err != nil {
				return nil, err
			}
		}
		fmt.Printf("PAIRING_CODE=%s\nAPPROVE_URL=%s\n", p.Code, p.ApproveURL)
		fmt.Println("Josh: open Dev > Devices, enter the code and approve with 2FA.")
		for {
			if time.Now().After(deadline) {
				return nil, errors.New("timed out waiting for pairing approval")
			}
			if p.ExpiresMs > 0 && time.Now().UnixMilli() > p.ExpiresMs {
				fmt.Fprintln(os.Stderr, "pairing code expired; starting a new one")
				_ = os.Remove(pairState)
				break
			}
			st, err := c.PollPairing(ctx, p.Code, p.PollSecret)
			if err != nil {
				return nil, explainHubError(err) // contract 4xx codes are final: no retry
			}
			switch st.State {
			case "approved":
				_ = os.Remove(pairState)
				return st, nil
			case "denied":
				_ = os.Remove(pairState)
				return nil, errors.New("pairing was denied in the dashboard")
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(3 * time.Second):
			}
		}
	}
	return nil, errors.New("pairing codes kept expiring; run devhub-pair again")
}

// certChainFrom returns the issued chain leaf-first, both parsed and as the store's exact bytes.
func certChainFrom(r *devhub.CertResponse) ([]core.Cert, []json.RawMessage, error) {
	if len(r.Certificate) == 0 {
		return nil, nil, errors.New("dev hub returned no certificate")
	}
	raw := []json.RawMessage{r.Certificate}
	for _, c := range r.Chain {
		if string(c) == string(r.Certificate) {
			continue
		}
		raw = append(raw, c)
	}
	chain := make([]core.Cert, len(raw))
	for i, b := range raw {
		if err := json.Unmarshal(b, &chain[i]); err != nil {
			return nil, nil, fmt.Errorf("certificate %d: %w", i, err)
		}
	}
	return chain, raw, nil
}

// checkMegaLeaf enforces QA M3 (final design): a developer leaf, for our Mega public key, whose subject
// equals the subject ra-core returned for the account byte for byte (core.EqualSubjectBytes).
func checkMegaLeaf(leaf *core.Cert, leafJSON []byte, megaPub []byte, serverSubject []byte) error {
	if leaf.Kind != "" && leaf.Kind != core.CertKindDeveloper {
		return fmt.Errorf("issued certificate kind %q, want %q", leaf.Kind, core.CertKindDeveloper)
	}
	if string(leaf.PublicKey) != string(megaPub) {
		return errors.New("issued certificate is not for our Mega public key")
	}
	return core.EqualSubjectBytes(leafJSON, serverSubject)
}

func writeJSON0600(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
