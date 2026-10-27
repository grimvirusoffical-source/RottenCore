package main

import "testing"

func TestValidateSign(t *testing.T) {
	if err := validateSign(true, true, false, "macos", []string{"app.zip"}); err != nil {
		t.Fatal(err)
	}
	if err := validateSign(true, false, true, "linux", []string{"app.zip"}); err != nil {
		t.Fatal(err)
	}
	if validateSign(false, true, false, "macos", []string{"app.zip"}) == nil {
		t.Fatal("lifetime")
	}
	if validateSign(true, true, true, "macos", []string{"app.zip"}) == nil {
		t.Fatal("both launcher flags")
	}
	if validateSign(true, false, false, "macos", []string{"app.zip"}) == nil {
		t.Fatal("neither launcher flag")
	}
	if validateSign(true, true, false, "", []string{"app.zip"}) == nil {
		t.Fatal("platform")
	}
	if validateSign(true, true, false, "macos", nil) == nil {
		t.Fatal("path")
	}
}
