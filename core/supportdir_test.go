package core

import (
	"path/filepath"
	"testing"
)

// L-a: ROTTENCORE_SUPPORT_DIR is an alias of ROTTENCORE_HOME (QuickLaunch honours both, in this order).
func TestSupportDirOverrideAndAlias(t *testing.T) {
	home, alias := filepath.Join(t.TempDir(), "home"), filepath.Join(t.TempDir(), "alias")

	t.Setenv("ROTTENCORE_HOME", "")
	t.Setenv("ROTTENCORE_SUPPORT_DIR", alias)
	if got := SupportDir(); got != alias {
		t.Fatalf("alias only: got %q, want %q", got, alias)
	}

	t.Setenv("ROTTENCORE_HOME", home)
	if got := SupportDir(); got != home {
		t.Fatalf("both set: ROTTENCORE_HOME must win, got %q", got)
	}

	t.Setenv("ROTTENCORE_SUPPORT_DIR", "")
	if got := SupportDir(); got != home {
		t.Fatalf("home only: got %q", got)
	}
}
