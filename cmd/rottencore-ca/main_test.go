package main

import (
	"os"
	"strings"
	"testing"

	"github.com/grimvirusoffical-source/RottenCore/ca"
	"github.com/grimvirusoffical-source/RottenCore/core"
)

const (
	joshRXA    = "rxa_LVWECFKVPN6XMPISHYONVY6WUB"
	supportRXA = "rxa_K2O7MTOWXQKPJSKNYG7RUUG2IR"
	someRXT    = "rxt_ABCDEFGHIJKLMNOPQRSTUVWX27"
)

func req(dev, team string) *ca.Request {
	return &ca.Request{Subject: core.CertSubject{Name: "Josh Franklinn", DevID: dev, TeamID: team}}
}

// Mega ids come from the server request subject; flags are only an optional cross-check; env never.
func TestMegaIDsFromRequest(t *testing.T) {
	t.Setenv("ROTTEN_DEV_ID", supportRXA) // must be ignored
	t.Setenv("ROTTEN_TEAM_ID", supportRXA)
	d, tm, err := megaIDsFromRequest(req(joshRXA, joshRXA), "", "")
	if err != nil || d != joshRXA || tm != joshRXA {
		t.Fatalf("got %q %q %v", d, tm, err)
	}
	if d, tm, err = megaIDsFromRequest(req(joshRXA, someRXT), joshRXA, someRXT); err != nil || tm != someRXT {
		t.Fatalf("matching cross-check refused: %v", err)
	}
	cases := []struct{ dev, team, xdev, xteam string }{
		{"A7", "T3", "", ""},                 // old ids in the request
		{joshRXA, supportRXA, "", ""},        // someone else's rxa_ as team
		{someRXT, someRXT, "", ""},           // team id in the dev slot
		{"", "", "", ""},                     // request without ids (no flag fallback)
		{joshRXA, joshRXA, supportRXA, ""},   // cross-check mismatch fails closed
		{joshRXA, joshRXA, "", someRXT},      // team cross-check mismatch
		{joshRXA, joshRXA, "A7", ""},         // malformed cross-check value
		{joshRXA, joshRXA, joshRXA[:29], ""}, // prefix of the right id
	}
	for _, c := range cases {
		if _, _, err := megaIDsFromRequest(req(c.dev, c.team), c.xdev, c.xteam); err == nil {
			t.Errorf("accepted request(%q,%q) cross(%q,%q)", c.dev, c.team, c.xdev, c.xteam)
		}
	}
}

func TestCAToolNeverReadsIDsFromEnv(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`Getenv("ROTTEN_DEV_ID")`, `Getenv("ROTTEN_TEAM_ID")`, `LookupEnv("ROTTEN_DEV_ID")`, `LookupEnv("ROTTEN_TEAM_ID")`} {
		if strings.Contains(string(b), bad) {
			t.Errorf("rottencore-ca reads %s", bad)
		}
	}
}
