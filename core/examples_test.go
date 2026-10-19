package core

import (
	"os"
	"testing"
)

func TestShippedManifestsParse(t *testing.T) {
	for _, p := range []string{"../examples/redx/rottencore.json", "../packaging/rottencore.json"} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseManifest(b); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}
