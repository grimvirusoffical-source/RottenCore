package core

import (
	"encoding/json"
	"errors"
	"testing"
)

const (
	joshRXA    = "rxa_LVWECFKVPN6XMPISHYONVY6WUB"
	supportRXA = "rxa_K2O7MTOWXQKPJSKNYG7RUUG2IR"
	someRXT    = "rxt_ABCDEFGHIJKLMNOPQRSTUVWX27"
)

func TestDevIDFormat(t *testing.T) {
	for _, ok := range []string{joshRXA, supportRXA, "rxa_AAAAAAAAAAAAAAAAAAAAAAAAAA", "rxa_22222222222222222222222222"} {
		if err := ValidateDevID(ok); err != nil {
			t.Errorf("valid %q refused: %v", ok, err)
		}
	}
	bad := []string{
		"", "A7", "A123", "T3", "7",
		"rxa_lvwecfkvpn6xmpishyonvy6wub",  // lower case
		"rxa_LVWECFKVPN6XMPISHYONVY6WU",   // 25
		"rxa_LVWECFKVPN6XMPISHYONVY6WUBA", // 27
		"rxa_LVWECFKVPN6XMPISHYONVY6WU1",  // 1 is not base32
		"rxa_LVWECFKVPN6XMPISHYONVY6WU8",  // 8 is not base32
		"RXA_LVWECFKVPN6XMPISHYONVY6WUB",
		"rxa-LVWECFKVPN6XMPISHYONVY6WUB",
		" rxa_LVWECFKVPN6XMPISHYONVY6WUB", joshRXA + " ", joshRXA + "\n", "x" + joshRXA,
		someRXT, // a team id in the dev slot
		"rxa_",
	}
	for _, b := range bad {
		if err := ValidateDevID(b); err == nil || !errors.Is(err, ErrBadID) {
			t.Errorf("bad dev id %q accepted", b)
		}
	}
}

func TestIDPairIndividualVsTeam(t *testing.T) {
	cases := []struct {
		dev, team string
		kind      TeamKind
		ok        bool
	}{
		{joshRXA, joshRXA, TeamIndividual, true},       // individual: team == owner's rxa_
		{joshRXA, someRXT, TeamOrg, true},              // team context
		{supportRXA, supportRXA, TeamIndividual, true}, // a second Mega account, not hard-coded
		{joshRXA, supportRXA, "", false},               // someone else's rxa_ as team
		{someRXT, someRXT, "", false},                  // rxt_ in the dev slot
		{joshRXA, "T3", "", false},                     // old team id
		{"A7", "T3", "", false},                        // old pair
		{joshRXA, "rxt_abcdefghijklmnopqrstuvwx27", "", false},
		{joshRXA, "rxt_ABCDEFGHIJKLMNOPQRSTUVWX2", "", false},
		{joshRXA, "rxt_ABCDEFGHIJKLMNOPQRSTUVWX277", "", false},
		{joshRXA, "rxo_ABCDEFGHIJKLMNOPQRSTUVWX27", "", false},
		{joshRXA, "", "", false},
	}
	for _, c := range cases {
		k, err := ValidateIDPair(c.dev, c.team)
		if (err == nil) != c.ok || (c.ok && k != c.kind) {
			t.Errorf("ValidateIDPair(%q,%q) = %q,%v; want ok=%v kind=%q", c.dev, c.team, k, err, c.ok, c.kind)
		}
	}
}

func TestEqualSubjectBytesIsExact(t *testing.T) {
	server := json.RawMessage(`{"name":"Josh Franklinn","teamId":"` + joshRXA + `","devId":"` + joshRXA + `"}`)
	cert := []byte(`{"version":1,"subject": {"name":"Josh Franklinn", "teamId":"` + joshRXA + `","devId":"` + joshRXA + `"},"kind":"developer"}`)
	if err := EqualSubjectBytes(cert, server); err != nil {
		t.Fatalf("identical subject (whitespace only) refused: %v", err)
	}
	near := []string{
		`{"name":"Josh Franklinn","teamId":"` + joshRXA + `","devId":"` + joshRXA[:len(joshRXA)-1] + `"}`, // prefix
		`{"name":"Josh Franklinn","teamId":"` + joshRXA + `","devId":"` + joshRXA + `X"}`,                 // longer
		`{"name":"josh franklinn","teamId":"` + joshRXA + `","devId":"` + joshRXA + `"}`,                  // case
		`{"teamId":"` + joshRXA + `","name":"Josh Franklinn","devId":"` + joshRXA + `"}`,                  // key order
		`{"name":"Josh Franklinn","teamId":"` + someRXT + `","devId":"` + joshRXA + `"}`,                  // rxt_ for rxa_
		`{"name":"Josh Franklinn ","teamId":"` + joshRXA + `","devId":"` + joshRXA + `"}`,                 // inner space
		`"` + joshRXA + `"`,
	}
	for _, n := range near {
		c := []byte(`{"subject":` + n + `}`)
		if err := EqualSubjectBytes(c, server); err == nil {
			t.Errorf("near-miss subject accepted: %s", n)
		}
	}
	if err := EqualSubjectBytes(cert, nil); err == nil {
		t.Error("empty server subject accepted")
	}
}

func TestSanityCheckSubject(t *testing.T) {
	good := json.RawMessage(`{"name":"Josh Franklinn","teamId":"` + joshRXA + `","devId":"` + joshRXA + `"}`)
	if _, k, err := SanityCheckSubject(good); err != nil || k != TeamIndividual {
		t.Fatalf("good subject: %v %v", k, err)
	}
	for _, b := range []string{
		`{"name":"x","teamId":"T3","devId":"A7"}`,
		`{"name":"x","teamId":"` + supportRXA + `","devId":"` + joshRXA + `"}`,
		`{"name":"x","teamId":"` + someRXT + `","devId":"` + someRXT + `"}`,
		`"CN=Josh"`,
	} {
		if _, _, err := SanityCheckSubject(json.RawMessage(b)); err == nil {
			t.Errorf("bad subject passed the sanity check: %s", b)
		}
	}
}

func TestValidateCrossCheckIDsOptional(t *testing.T) {
	ok := [][2]string{{"", ""}, {joshRXA, ""}, {"", someRXT}, {"", joshRXA}, {joshRXA, joshRXA}, {joshRXA, someRXT}}
	for _, c := range ok {
		if err := ValidateCrossCheckIDs(c[0], c[1]); err != nil {
			t.Errorf("ValidateCrossCheckIDs(%q,%q) refused: %v", c[0], c[1], err)
		}
	}
	bad := [][2]string{{"A7", ""}, {"", "T3"}, {"A7", "T3"}, {joshRXA, supportRXA}, {someRXT, ""}, {"rxa_lower", ""}, {"", "rxt_ABC"}}
	for _, c := range bad {
		if err := ValidateCrossCheckIDs(c[0], c[1]); err == nil {
			t.Errorf("ValidateCrossCheckIDs(%q,%q) accepted", c[0], c[1])
		}
	}
}
