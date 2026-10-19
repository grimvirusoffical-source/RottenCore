package devhub

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLiveCAChainGET hits production /v1/devhub/ca/chain read-only. Opt-in (QA L3): it runs only with
// RA_DEVHUB_LIVE=1, so the default test run is hermetic (no network).
func TestLiveCAChainGET(t *testing.T) {
	if os.Getenv("RA_DEVHUB_LIVE") != "1" {
		t.Skip("live dev-hub test: set RA_DEVHUB_LIVE=1 to run (network)")
	}
	base := os.Getenv("RA_DEVHUB_URL")
	if base == "" {
		base = "https://api.rottenapplestore.org"
	}
	c := &Client{BaseURL: base}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	info, err := c.CAChainInfo(ctx)
	if err != nil {
		t.Fatalf("ca/chain: %v", err)
	}
	t.Logf("ca/chain issuing=%v production=%v chain_len=%d launcher=%s", info.Issuing, info.Production, len(info.Chain), LauncherVersion)
	if !info.Production {
		t.Fatalf("expected production=true, got %+v", info)
	}
	// issuing may be false until the chain is loaded — that is OK for this read-only probe
	if LauncherVersion < "0.2.0" && LauncherVersion != "0.2.0" {
		// string compare is weak; ensure constant is exactly HubMinLauncher floor
		t.Fatalf("LauncherVersion %q must be >= 0.2.0", LauncherVersion)
	}
	if LauncherVersion != "0.2.0" && LauncherVersion[0] == '0' && len(LauncherVersion) >= 5 && LauncherVersion < "0.2.0" {
		t.Fatalf("LauncherVersion too old: %s", LauncherVersion)
	}
}
