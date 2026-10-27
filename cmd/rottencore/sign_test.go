package main

import "testing"

func TestValidateSign(t *testing.T) {
	if err := validateSign(true, false, true, false, "macos", []string{"app.zip"}); err != nil {
		t.Fatal(err)
	}
	if err := validateSign(true, false, false, true, "linux", []string{"app.zip"}); err != nil {
		t.Fatal(err)
	}
	if err := validateSign(false, true, true, false, "macos", []string{"app.zip"}); err != nil {
		t.Fatal(err)
	}
	if validateSign(false, false, true, false, "macos", []string{"app.zip"}) == nil {
		t.Fatal("mode")
	}
	if validateSign(true, true, true, false, "macos", []string{"app.zip"}) == nil {
		t.Fatal("both modes")
	}
	if validateSign(false, true, false, true, "macos", []string{"app.zip"}) == nil {
		t.Fatal("developer without launcher")
	}
	if validateSign(true, false, true, true, "macos", []string{"app.zip"}) == nil {
		t.Fatal("both launcher flags")
	}
	if validateSign(true, false, false, false, "macos", []string{"app.zip"}) == nil {
		t.Fatal("neither launcher flag")
	}
	if validateSign(true, false, true, false, "", []string{"app.zip"}) == nil {
		t.Fatal("platform")
	}
	if validateSign(true, false, true, false, "macos", nil) == nil {
		t.Fatal("path")
	}
}
