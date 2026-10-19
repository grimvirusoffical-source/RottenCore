package ca

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The ra-core contract is final (RottenApple rxa-cert-ids @ 711171b): X-RedX-Accounts-Key,
// GET /v1/devhub/account-status {account,cert,contexts}, rxa_/rxt_ ids, the compact {name,teamId,devId}
// subject. No Go source, rollout script or rollout doc may still call any of it PENDING / placeholder.
var (
	todoContractRe = regexp.MustCompile(`(?i)TODO\(contract\)`)
	placeholderRe  = regexp.MustCompile(`(?i)\bplace-?holders?\b`)
	upperPendingRe = regexp.MustCompile(`\bPENDING\b`)
	shPendingVarRe = regexp.MustCompile(`\bPENDING(=\(|\+=|\[[@*]\])|#PENDING\[`) // phase-sign's work-list array
	lowerPendingRe = regexp.MustCompile(`(?i)\bpending\b`)
	contractWordRe = regexp.MustCompile(`(?i)header|x-redx|account-?status|subject|layout|shape|team.?id|dev.?id|format|contract|grok bot|\brx[at]_|field|\bapi\b|\bids\b|accounts key|endpoint|\bpath\b`)
)

func contractPendingViolation(line string) bool {
	if todoContractRe.MatchString(line) || placeholderRe.MatchString(line) {
		return true
	}
	if upperPendingRe.MatchString(shPendingVarRe.ReplaceAllString(line, "")) {
		return true
	}
	return lowerPendingRe.MatchString(line) && contractWordRe.MatchString(line)
}

func TestNoContractPendingLeft(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..")
	var files []string
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if info.IsDir() && (rel == ".git" || rel == "apple" || strings.HasPrefix(rel, "apple/")) {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "no_pending_contract_test.go") ||
			strings.HasPrefix(rel, "scripts/") && (strings.HasSuffix(p, ".sh") || strings.HasSuffix(p, ".md") && !strings.HasSuffix(p, "inventory.md")) || // inventory.md is generated asset data
			strings.HasPrefix(rel, "docs/") && strings.HasSuffix(p, ".md") {
			files = append(files, p)
		}
		return nil
	})
	if len(files) < 50 {
		t.Fatalf("scanned only %d files", len(files))
	}
	for _, p := range files {
		b, _ := os.ReadFile(p)
		for i, line := range strings.Split(string(b), "\n") {
			if contractPendingViolation(line) {
				rel, _ := filepath.Rel(root, p)
				t.Errorf("%s:%d still marks the ra-core contract as pending: %s", rel, i+1, strings.TrimSpace(line))
			}
		}
	}
}

func TestContractPendingRuleFixtures(t *testing.T) {
	bad := []string{
		`// PENDING (Grok Bot): header name and API shape are placeholders until ra-core's commit lands.`,
		`return errors.New("ra-core returned no account subject (PENDING API shape)")`,
		`// AccountStatusPath is the signing-time identity check. PENDING: placeholder path.`,
		`# PENDING (Grok Bot): the team format.`,
		`// TODO(contract): field names`,
		`// the subject layout is still pending`,
		`fmt.Errorf("ra-core subject is not the expected object (PENDING layout): %w", err)`,
	}
	for _, l := range bad {
		if !contractPendingViolation(l) {
			t.Errorf("missed: %s", l)
		}
	}
	ok := []string{
		`State    string ` + "`json:\"state\"`" + ` // pending | approved | denied`,
		`st := "pending"`,
		`return nil, fmt.Errorf("no pending device %q", id)`,
		`PENDING=()`,
		`  PENDING+=("$MARK|$LOCAL")`,
		`if [[ ${#PENDING[@]} -gt 0 ]]; then`,
		`  for item in "${PENDING[@]}"; do`,
		`@Published var pendingBuild: BuildConfirmPreview?`,
		`return nil, fmt.Errorf("the pairing is still pending; approve code %s in your Rotten Apple dev dashboard", d.PairingCode)`,
	}
	for _, l := range ok {
		if contractPendingViolation(l) {
			t.Errorf("false positive: %s", l)
		}
	}
}
