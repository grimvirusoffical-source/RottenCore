package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grimvirusoffical-source/RottenCore/builder"
)

// The Mac signs only macOS and iOS builds: sign-batch refuses the whole list if any line is another platform.
func TestSignBatchRefusesNonMacIOS(t *testing.T) {
	ok := [][4]string{
		{"/s/redx-0.4.5-macos-universal.dmg", "com.redx.redx", "0.4.5", builder.PlatformMacArm64},
		{"/s/quicklaunch-cli-1.0.0-beta.1-darwin-amd64", "com.redx.quicklaunch", "1.0.0-beta.1", builder.PlatformMacIntel},
		{"/s/App-1.0.ipa", "com.redx.app", "1.0", builder.PlatformIOS},
		{"/s/redx-0.4.5-macos-arm64.pkg", "com.redx.redx", "0.4.5", ""}, // detected from the name
	}
	if err := requireMacIOSBatch(ok); err != nil {
		t.Fatalf("mac/iOS batch refused: %v", err)
	}
	for _, bad := range [][4]string{
		{"/s/redx_0.4.5_amd64.deb", "x", "1", builder.PlatformLinux},
		{"/s/redx-0.4.5-linux-amd64.tar.gz", "x", "1", ""},
		{"/s/rotten-apple-extension-0.1.0.zip", "x", "1", builder.PlatformExtensions},
		{"/s/redx-0.4.5-windows-amd64-setup.exe", "x", "1", builder.PlatformWindows},
		{"/s/GenDragoon-Android.apk", "x", "1", builder.PlatformAndroid},
		{"/s/mystery.bin", "x", "1", ""},
		{"/s/redx-0.4.5-macos-arm64.dmg", "x", "1", "linux"}, // the explicit column wins
	} {
		err := requireMacIOSBatch(append(append([][4]string{}, ok...), bad))
		if err == nil || !strings.Contains(err.Error(), filepath.Base(bad[0])) {
			t.Errorf("%v: batch not refused (%v)", bad, err)
		}
	}
}

// The shipped inventory: every sign_on_mac entry is macOS/iOS; every non-Mac platform is deferred with a reason.
func TestInventoryIsMacIOSOnly(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "scripts", "rollout", "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		Sign     []map[string]interface{} `json:"sign_on_mac"`
		Deferred []map[string]interface{} `json:"deferred"`
		Old      interface{}              `json:"deferred_windows_android"`
	}
	if err := json.Unmarshal(b, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.Old != nil {
		t.Error("stale deferred_windows_android list")
	}
	if len(inv.Sign) != 21 {
		t.Errorf("sign_on_mac = %d, want 21", len(inv.Sign))
	}
	for _, a := range inv.Sign {
		c := a["category"].(string)
		if c != "mac" && c != "ios" {
			t.Errorf("%v marked sign_on_mac with category %s", a["asset"], c)
		}
	}
	reasons := map[string]string{"linux": "no Linux signing host", "extension": "no browser-extension signing host", "windows": "Windows signing host", "android": "Windows signing host"}
	for _, a := range inv.Deferred {
		c := a["category"].(string)
		if want, ok := reasons[c]; !ok || !strings.Contains(a["reason"].(string), want) {
			t.Errorf("deferred %v (%s) reason %v", a["asset"], c, a["reason"])
		}
	}
}
