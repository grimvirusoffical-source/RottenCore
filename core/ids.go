package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// Red-XAI Accounts identifiers for dev-hub (Mega) certificate subjects. Everything about the id formats,
// the Accounts key format and the subject layout lives in this file. Contract: RottenApple rxa-cert-ids @
// 711171b (DEV_HUB_API.md §4 / §4a). The tests in ids_test.go pin the behaviour.

// DevIDPattern is a Red-XAI Accounts OIDC sub: "rxa_" + 26 upper-case base32 characters (A-Z, 2-7).
const DevIDPattern = `^rxa_[A-Z2-7]{26}$`

// TeamKind says which kind of team slot a team id fills.
type TeamKind string

const (
	TeamIndividual TeamKind = "individual" // the owner's own rxa_ id; must equal the dev id
	TeamOrg        TeamKind = "team"       // a team/org id
)

// TeamIDPattern is one accepted team-id format.
type TeamIDPattern struct {
	Kind    TeamKind
	Pattern string // anchored regexp
}

// TeamIDPatterns is the list of accepted team-id formats, checked in order (final: individual = the
// owner's rxa_, team = rxt_ made once by ra-core). Edit only here (and lib.sh, kept in sync by a test).
var TeamIDPatterns = []TeamIDPattern{
	{Kind: TeamIndividual, Pattern: DevIDPattern},  // individual context: team == owner's rxa_
	{Kind: TeamOrg, Pattern: `^rxt_[A-Z2-7]{26}$`}, // team: "rxt_" + 26 base32
}

var devIDRe = regexp.MustCompile(DevIDPattern)

// ErrBadID is wrapped by every id validation failure.
var ErrBadID = errors.New("invalid Red-XAI id")

// ValidateDevID checks a dev id against DevIDPattern (full-string, anchored).
func ValidateDevID(id string) error {
	if !devIDRe.MatchString(id) {
		return fmt.Errorf("%w: dev id %q must match %s (Red-XAI Accounts sub; old A<n> ids are not accepted)", ErrBadID, id, DevIDPattern)
	}
	return nil
}

// TeamKindOf returns the kind of a syntactically valid team id.
func TeamKindOf(team string) (TeamKind, error) {
	for _, p := range TeamIDPatterns {
		if regexp.MustCompile(p.Pattern).MatchString(team) {
			return p.Kind, nil
		}
	}
	return "", fmt.Errorf("%w: team id %q matches none of the accepted team formats %v (old T<n> ids are not accepted)", ErrBadID, team, teamPatternList())
}

func teamPatternList() []string {
	var s []string
	for _, p := range TeamIDPatterns {
		s = append(s, p.Pattern)
	}
	return s
}

// ValidateIDPair validates a (dev, team) pair: the dev id is valid, the team id is valid, and an
// individual-kind team id (an rxa_) is only allowed when it is exactly the dev id.
func ValidateIDPair(dev, team string) (TeamKind, error) {
	if err := ValidateDevID(dev); err != nil {
		return "", err
	}
	k, err := TeamKindOf(team)
	if err != nil {
		return "", err
	}
	if k == TeamIndividual && team != dev {
		return "", fmt.Errorf("%w: individual team id %q must equal the dev id %q", ErrBadID, team, dev)
	}
	return k, nil
}

// AccountsKeyPattern is the ra-core-issued Red-XAI Accounts key: ra_sk_live_ + 43 base62.
const AccountsKeyPattern = `^ra_sk_live_[A-Za-z0-9]{43}$`

var accountsKeyRe = regexp.MustCompile(AccountsKeyPattern)

// ValidateAccountsKeyFormat checks the key bytes without ever putting them in the error.
func ValidateAccountsKeyFormat(k []byte) error {
	if !accountsKeyRe.Match(k) {
		return fmt.Errorf("that is not a Red-XAI Accounts key (expected ra_sk_live_ + 43 letters/digits, %d characters; got %d characters). Create one on the Dev page: API keys > Red-XAI Accounts key", 11+43, len(k))
	}
	return nil
}

// ---- Subject layout (final): {"name":"<team name>","teamId":"…","devId":"…"}, Go encoding/json, compact ----

// SubjectIDs extracts (dev, team) from a decoded subject. This is the ONE place that knows where the ids
// sit: subject.devId / subject.teamId.
func SubjectIDs(s CertSubject) (dev, team string) {
	return s.DevID, s.TeamID
}

// CertSubjectBytes returns the "subject" member of a certificate exactly as the store serialised it.
func CertSubjectBytes(certJSON []byte) (json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(certJSON, &m); err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	sub, ok := m["subject"]
	if !ok || len(sub) == 0 {
		return nil, errors.New("certificate has no subject")
	}
	return sub, nil
}

// EqualSubjectBytes is the exact-match rule (QA M3, final contract): the "subject" member of the issued
// certificate, exactly as ra-core serialised it, must equal ra-core's cert.subject string byte for byte.
// Both are compact Go encoding/json output, so there is no whitespace tolerance and nothing is rebuilt here.
func EqualSubjectBytes(certJSON []byte, serverSubject []byte) error {
	got, err := CertSubjectBytes(certJSON)
	if err != nil {
		return err
	}
	if len(serverSubject) == 0 || bytes.Equal(serverSubject, []byte("null")) {
		return errors.New("ra-core returned no subject to compare against")
	}
	if !bytes.Equal(got, serverSubject) {
		return fmt.Errorf("certificate subject %s != ra-core subject %s (byte-for-byte match required)", got, serverSubject)
	}
	// The member as stored must also be the compact `"subject":<bytes>` (no whitespace around the value).
	if !bytes.Contains(certJSON, append([]byte(`"subject":`), serverSubject...)) {
		return errors.New("certificate subject member is not compact (byte-for-byte match required)")
	}
	return nil
}

// SanityCheckSubject is the LOOSE check on the server-returned subject fields: devId must look like an
// rxa_ sub and teamId must match one of TeamIDPatterns (an rxa_ team only as the individual owner).
// It never replaces EqualSubjectBytes.
func SanityCheckSubject(serverSubject json.RawMessage) (CertSubject, TeamKind, error) {
	var s CertSubject
	if err := json.Unmarshal(serverSubject, &s); err != nil {
		return s, "", fmt.Errorf("ra-core subject is not the expected object (contract: {name,teamId,devId}): %w", err)
	}
	dev, team := SubjectIDs(s)
	k, err := ValidateIDPair(dev, team)
	return s, k, err
}

// ValidateCrossCheckIDs validates the OPTIONAL ids Josh may export (ROTTEN_DEV_ID / ROTTEN_TEAM_ID).
// Identity comes only from the ra-core subject Josh confirms; these are an extra exact cross-check that
// fails closed on mismatch. Both empty is fine (no cross-check); anything set must be well formed.
func ValidateCrossCheckIDs(dev, team string) error {
	switch {
	case dev == "" && team == "":
		return nil
	case dev != "" && team != "":
		_, err := ValidateIDPair(dev, team)
		return err
	case dev != "":
		return ValidateDevID(dev)
	default:
		_, err := TeamKindOf(team)
		return err
	}
}
