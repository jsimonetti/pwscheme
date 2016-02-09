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
	var hash string
	var err error
	var res bool

	if hash, err = ssha.Generate(pass); err != nil {
		t.Error("Generate password fails", err)
		return
	}

	if res, err = ssha.Validate(pass, hash); err != nil && res != false {
		t.Error("Validate password fails", err)
	}
}
