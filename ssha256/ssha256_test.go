package ssha256_test

import (
	"testing"

	"github.com/jsimonetti/pwscheme/ssha256"
)

func TestValidate(t *testing.T) {
	pass := "test123"
	hash := "{SSHA256}czO44OTV17PcF1cRxWrLZLy9xHd7CWyVYplr1rOhuMlx/7IK"

	if res, err := ssha256.Validate(pass, hash); res != true {
		t.Error("Validate password fails", err)
	}
}

func TestGenerate(t *testing.T) {
	pass := "test123"
	var hash string
	var err error
	var res bool

	if hash, err = ssha256.Generate(pass, 8); err != nil {
		t.Error("Generate password fails", err)
		return
	}

	if res, err = ssha256.Validate(pass, hash); err != nil && res != false {
		t.Error("Validate password fails", err)
	}
}
