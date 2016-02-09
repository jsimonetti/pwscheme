package ssha_test

import (
	"testing"

	"github.com/jsimonetti/pwscheme/ssha"
)

func TestValidate(t *testing.T) {
	pass := "test123"
	hash := "{SSHA}JFZFs0oHzxbMwkSJmYVeI8MnTDy/276a"

	if res, err := ssha.Validate(pass, hash); res != true {
		t.Error("Validate password fails", err)
	}
}

func TestGenerate(t *testing.T) {
	pass := "test123"
	hash := ssha.Generate(pass)

	if res, err := ssha.Validate(pass, hash); res != true {
		t.Error("Generate of password fails", err)
	}
}
