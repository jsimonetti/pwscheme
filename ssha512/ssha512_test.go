package ssha512_test

import (
	"testing"

	"github.com/jsimonetti/pwscheme/ssha512"
)

func TestValidate(t *testing.T) {
	pass := "test123"
	hash := "{SSHA512}xPUl/px+1cG55rUH4rzcwxdOIPSB2TingLpiJJumN2xyDWN4Ix1WQG3ihnvHaWUE8MYNkvMi5rf0C9NYixHsE6Yh59M="

	if res, err := ssha512.Validate(pass, hash); res != true {
		t.Error("Validate password fails", err)
	}
}

func TestGenerate(t *testing.T) {
	pass := "test123"
	var hash string
	var err error
	var res bool

	if hash, err = ssha512.Generate(pass, 8); err != nil {
		t.Error("Generate password fails", err)
		return
	}

	if res, err = ssha512.Validate(pass, hash); err != nil && res != false {
		t.Error("Validate password fails", err)
	}
}
