package ca

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestKeychainDarwinSourceKeepsSecretsOffArgv is a static audit: the darwin Keychain Put path must not
// pass the private-key blob as an argv element of `security` (QA blocker: visible in `ps`).
func TestKeychainDarwinSourceKeepsSecretsOffArgv(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller")
	}
	src := filepath.Join(filepath.Dir(file), "keychain_darwin.go")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	// Forbidden: exec.Command("security", …, "-w", <something that includes the blob variable>)
	// Allowed: security -i with the blob only on stdin.
	if !strings.Contains(text, `exec.Command("/usr/bin/security", "-i")`) {
		t.Fatal(`Put must invoke exec.Command("/usr/bin/security", "-i") so the secret rides on stdin, not argv`)
	}
	// QA L-b: never a PATH-relative security (a same-user PATH shim would get the key blob on stdin).
	if regexp.MustCompile(`exec\.Command(Context)?\(\s*(ctx,\s*)?"security"`).MatchString(text) {
		t.Fatal(`keychain_darwin.go must exec /usr/bin/security by absolute path`)
	}
	// Any Command("security", ...) whose arg list includes "-w" next to a non-literal is a regression.
	re := regexp.MustCompile(`exec\.Command\(\s*"/usr/bin/security"\s*,([^)]*)\)`)
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		args := m[1]
		if strings.Contains(args, `"-i"`) || strings.Contains(args, `"find-generic-password"`) {
			continue // -i has no secret in argv; find -w prints to stdout
		}
		if strings.Contains(args, `"-w"`) {
			t.Fatalf("security argv still includes -w (secret risk): exec.Command(\"security\", %s)", args)
		}
	}
}

// The only lines in the rollout scripts that may touch secrets, matched exactly after trimming (QA M2).
// Anything else that reads a Keychain secret (-w), prints a secret variable, or builds an Authorization
// header fails the audit.
var allowedSecretLines = map[string]bool{
	// lib.sh load_github_token: one Keychain read into an unexported shell variable.
	`GH_RELEASE_TOKEN=$(/usr/bin/security find-generic-password -a github-token -s "${KEYCHAIN_SERVICE:-com.redx.rottencore.ca}" -w) \`: true,
	// lib.sh curl_github: the header goes to curl on stdin (-H @-).
	`printf 'Authorization: Bearer %s\n' "$GH_RELEASE_TOKEN" | curl -sS -L --fail \`: true,
	// lib.sh load_github_token: move a session token into the unexported variable.
	`GH_RELEASE_TOKEN="$GITHUB_TOKEN"`: true,
	// lib.sh: hidden prompt.
	`read -r -s -p "GitHub token (input hidden): " GH_RELEASE_TOKEN; echo >&2`: true,
	// publish.sh / restore.sh (python): token popped from env, sent to curl on stdin.
	`token = os.environ.pop("GITHUB_TOKEN")`:                                                                     true,
	`AUTH_LINE = f"Authorization: Bearer {token}\n"`:                                                             true,
	`return subprocess.run(["curl", "-sS", "-H", "@-", *args], input=AUTH_LINE, capture_output=True, text=True)`: true,
}

var (
	shVarRe     = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)`)
	secretWords = map[string]bool{"KEY": true, "SECRET": true, "SEED": true, "PRIV": true, "PRIVATE": true,
		"TOKEN": true, "PASSWORD": true, "PASS": true, "PW": true, "BLOB": true, "PASSPHRASE": true, "SK": true}
	secretFlagRe   = regexp.MustCompile(`(^|\s)-[A-Za-z]*[wg][A-Za-z]*(\s|$|\))`)
	pyListSecretRe = regexp.MustCompile(`["']/?(usr/bin/)?security["']` + `.*["']-[A-Za-z]*[wg][A-Za-z]*["']`)
	keySubstRe     = regexp.MustCompile(`--(key|seed|priv[a-z]*|secret|token)[= ]+["']?\$\(|\$\(\s*(cat|<)\s*[^)]*(key|seed|priv|secret|token)`)
	accountsReadRe = regexp.MustCompile(`(?i)\bread\b.*accounts`)
	exportRe       = regexp.MustCompile(`(^|[;&\s])export\s+([A-Za-z_][A-Za-z0-9_]*)`)
	printVerbRe    = regexp.MustCompile(`(^|[;&|(\s])(echo|printf|log|cat|tee|print)\b|print\(`)
)

// secretVar reports whether a shell variable name looks like it holds key material or a credential:
// one of its _-separated words is KEY, SECRET, TOKEN, … (KEYCHAIN_SERVICE is fine).
func secretVar(name string) bool {
	for _, w := range strings.Split(strings.ToUpper(name), "_") {
		if secretWords[w] {
			return true
		}
	}
	return false
}

// auditRolloutScript returns every violation in one script.
func auditRolloutScript(name, text string) []string {
	var bad []string
	add := func(i int, why, line string) { bad = append(bad, fmt.Sprintf("%s:%d: %s: %s", name, i+1, why, line)) }
	for i, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if allowedSecretLines[trim] {
			continue
		}
		low := strings.ToLower(trim)
		switch {
		case strings.Contains(trim, "add-generic-password"):
			add(i, "writes a Keychain item from a script (use rottencore --keychain)", trim)
		case strings.Contains(trim, "security") && secretFlagRe.MatchString(trim):
			// -w, combined flags like -wa / -aw, and -g (password to stderr) (QA L-a)
			add(i, "reads a Keychain secret outside the allow-list", trim)
		case pyListSecretRe.MatchString(trim):
			add(i, "Python/list-form security call with -w/-g (QA L-a)", trim)
		case keySubstRe.MatchString(trim):
			add(i, "key material substituted into argv via $(…) (QA L-a)", trim)
		case strings.Contains(low, "redx-accounts-api-key") || strings.Contains(low, "x-redx-accounts-key") || strings.Contains(low, "--accounts-key"):
			add(i, "Red-XAI Accounts key handled by a script (typed at rottencore's tty prompt only)", trim)
		case accountsReadRe.MatchString(trim):
			add(i, "script reads the Red-XAI Accounts key (rottencore prompts on /dev/tty itself)", trim)
		case strings.Contains(trim, "dump-keychain") || strings.Contains(trim, "security export"):
			add(i, "exports Keychain contents", trim)
		case strings.Contains(trim, "Authorization:") || strings.Contains(low, "bearer "):
			add(i, "builds an Authorization header outside the allow-list (use curl_github / run_curl)", trim)
		case regexp.MustCompile(`(^|\s)set\s+-[a-z]*x`).MatchString(trim) || strings.Contains(trim, "xtrace"):
			add(i, "xtrace would echo secrets", trim)
		case strings.Contains(low, "nacl") || strings.Contains(low, "signingkey("):
			add(i, "Python key handling (keys stay in the Go binary, QA F1)", trim)
		}
		for _, m := range shVarRe.FindAllStringSubmatch(trim, -1) {
			if !secretVar(m[1]) {
				continue
			}
			if printVerbRe.MatchString(trim) {
				add(i, "prints secret variable $"+m[1], trim)
			}
			if strings.Contains(trim, "curl") {
				add(i, "secret variable $"+m[1]+" on a curl command line", trim)
			}
		}
		for _, m := range exportRe.FindAllStringSubmatch(trim, -1) {
			if secretVar(m[2]) {
				add(i, "exports secret variable "+m[2]+" into child environments", trim)
			}
		}
		// python heredocs: never print a token / key value
		if strings.Contains(trim, "print(") && regexp.MustCompile(`\b(token|AUTH_LINE|api_key|seed|priv)\b`).MatchString(trim) {
			add(i, "prints a secret from Python", trim)
		}
	}
	return bad
}

func rolloutScriptsDir(t *testing.T) string {
	t.Helper()
	if env, ok := os.LookupEnv("MAC_SIGN_SH"); ok {
		// QA L7: an explicit path that does not exist is a failure, not a silent fallback.
		if _, err := os.Stat(env); err != nil {
			t.Fatalf("MAC_SIGN_SH=%s does not exist", env)
		}
		return filepath.Dir(env)
	}
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "..", "scripts", "rollout")
	if _, err := os.Stat(filepath.Join(dir, "mac-sign.sh")); err != nil {
		t.Fatalf("rollout scripts not found at %s: %v", dir, err)
	}
	return dir
}

// TestMacSignScriptKeepsKeyMaterialOffArgv audits every rollout script with the strict rules above.
func TestMacSignScriptKeepsKeyMaterialOffArgv(t *testing.T) {
	dir := rolloutScriptsDir(t)
	entries, err := filepath.Glob(filepath.Join(dir, "*.sh"))
	if err != nil || len(entries) < 8 {
		t.Fatalf("expected the rollout scripts in %s, got %v (%v)", dir, entries, err)
	}
	var combined strings.Builder
	for _, path := range entries {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		combined.Write(b)
		for _, v := range auditRolloutScript(filepath.Base(path), string(b)) {
			t.Error(v)
		}
	}
	text := combined.String()
	if !strings.Contains(text, "--keychain") {
		t.Fatalf("%s scripts should use --keychain so keys stay in the Keychain", dir)
	}
	pair, _ := os.ReadFile(filepath.Join(dir, "phase-pair.sh"))
	if strings.Contains(string(pair), "python3 - ") || strings.Contains(string(pair), "find-generic-password") {
		t.Fatal("phase-pair.sh must pair through `rottencore devhub-pair` (no Python, no Keychain reads in shell)")
	}
	if !strings.Contains(string(pair), "devhub-pair") {
		t.Fatal("phase-pair.sh must call rottencore devhub-pair")
	}
}

// TestRolloutAuditCatchesLeaks proves the audit is not toothless (QA M2): each of these must fail it.
func TestRolloutAuditCatchesLeaks(t *testing.T) {
	bad := []string{
		`echo "$RA_API_KEY"`,
		`printf '%s\n' "$GH_RELEASE_TOKEN" > /tmp/t`,
		`printf '%s' "${DEVICE_SEED}" | xxd`,
		`log "key=$PRIV_BLOB"`,
		`echo $KEY`,
		`K=$(security find-generic-password -a josh-mega -s svc -w)`,
		`security add-generic-password -a x -s y -w "$B"`,
		`curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com`,
		`curl -u "x:$GH_RELEASE_TOKEN" https://api.github.com`,
		`export RA_API_KEY`,
		`set -x`,
		`from nacl.signing import SigningKey`,
		`print(token)`,
		`cat <<<"$MEGA_PRIVATE"`,
		// QA L-a: the four rarer patterns
		`K=$(security find-generic-password -wa josh-mega -s svc)`,
		`security find-generic-password -a josh-mega -s svc -g`,
		`subprocess.check_output(["security", "find-generic-password", "-a", "josh-mega", "-w"])`,
		`"$ROTTENCORE_CA" sign --key "$(cat key.hex)" f`,
		// Red-XAI Accounts key: never handled by a script
		`read -r -s REDX_ACCOUNTS_KEY`,
		`echo "$REDX_ACCOUNTS_KEY" | rottencore devhub-pair`,
		`export REDX_ACCOUNTS_KEY`,
		`security find-generic-password -a redx-accounts-api-key -s svc`,
		`curl -H "X-RedX-Accounts-Key: $K" https://api.rottenapplestore.org`,
		`rottencore devhub-pair --accounts-key "$K"`,
		`printf '%s\n' "$ACCOUNTS_TOKEN" | curl -H @- x`,
	}
	for _, line := range bad {
		if len(auditRolloutScript("fixture.sh", line+"\n")) == 0 {
			t.Errorf("audit missed: %s", line)
		}
	}
	ok := []string{
		`security find-generic-password -a "$label" -s "${KEYCHAIN_SERVICE:-com.redx.rottencore.ca}" >/dev/null 2>&1`,
		`"$ROTTENCORE" sign-batch "$BATCH" --keychain --label josh-mega --service "$KEYCHAIN_SERVICE" \`,
		`echo "ROOT_FINGERPRINT=$ROOT_FP"`,
		`/usr/bin/security find-generic-password -a "$label" -s "${KEYCHAIN_SERVICE:-com.redx.rottencore.ca}" >/dev/null 2>&1`,
		`echo ">> You will also be asked for the Red-XAI Accounts full-access key (hidden; not stored) and to type yes." >&2`,
	}
	for _, line := range ok {
		if v := auditRolloutScript("fixture.sh", line+"\n"); len(v) != 0 {
			t.Errorf("audit false positive: %v", v)
		}
	}
}
