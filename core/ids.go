package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// Red-XAI Accounts identifiers for dev-hub (Mega) certificate subjects. EVERYTHING about the id formats
// and the subject layout lives in this file so it is one edit when the final formats land.
//
// PENDING (Grok Bot): the team id format and the exact subject layout are not final. Edit TeamIDPatterns
// and SubjectIDs below when the confirmed format arrives; the tests in ids_test.go pin the behaviour.

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

// TeamIDPatterns is the (PENDING) list of accepted team-id formats, checked in order. To accept a central
// Accounts org id later, append its anchored pattern with Kind TeamOrg.
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

// ---- Subject layout (PENDING: Grok Bot sends the exact layout with the ra-core commit) ----

// SubjectIDs extracts (dev, team) from a decoded subject. This is the ONE place that knows where the ids
// sit; today the store puts the raw ids in subject.devId / subject.teamId.
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

// EqualSubjectBytes is the exact-match rule (QA M3, final design): the issued certificate's subject must
// equal the subject ra-core returned for the account, byte for byte. Only insignificant JSON whitespace
// is removed (json.Compact); key order, case, spacing inside strings and every character must match.
// No value is rebuilt on this side.
func EqualSubjectBytes(certJSON []byte, serverSubject json.RawMessage) error {
	got, err := CertSubjectBytes(certJSON)
	if err != nil {
		return err
	}
	var a, b bytes.Buffer
	if err := json.Compact(&a, got); err != nil {
		return fmt.Errorf("certificate subject: %w", err)
	}
	if len(bytes.TrimSpace(serverSubject)) == 0 {
		return errors.New("ra-core returned no subject to compare against")
	}
	if err := json.Compact(&b, serverSubject); err != nil {
		return fmt.Errorf("ra-core subject: %w", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		return fmt.Errorf("certificate subject %s != ra-core subject %s (byte-for-byte match required)", a.String(), b.String())
	}
	return nil
}

// SanityCheckSubject is the LOOSE check on the server-returned subject fields: devId must look like an
// rxa_ sub and teamId must match one of TeamIDPatterns (an rxa_ team only as the individual owner).
// It never replaces EqualSubjectBytes.
func SanityCheckSubject(serverSubject json.RawMessage) (CertSubject, TeamKind, error) {
	var s CertSubject
	if err := json.Unmarshal(serverSubject, &s); err != nil {
		return s, "", fmt.Errorf("ra-core subject is not the expected object (PENDING layout): %w", err)
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
