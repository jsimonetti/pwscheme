package ssha256_test

import (
	"testing"

	"github.com/jsimonetti/pwscheme/ssha256"
)

func TestValidPassword(t *testing.T) {
	pass := "test123"
	hash := "{SSHA256}czO44OTV17PcF1cRxWrLZLy9xHd7CWyVYplr1rOhuMlx/7IK"

	if res, err := ssha256.Validate(pass, hash); err != nil || res != true {
		t.Errorf("Valid password fails validation: %s", err)
	}
}

func TestInValidPassword(t *testing.T) {
	pass := "test12"
	hash := "{SSHA256}czO44OTV17PcF1cRxWrLZLy9xHd7CWyVYplr1rOhuMlx/7IK"

	if res, err := ssha256.Validate(pass, hash); res != false {
		t.Errorf("Invalid password passes validation: %s", err)
	}
}

func TestGenerate4(t *testing.T) {
	pass := "test123"
	var hash string
	var err error
	var res bool

	if hash, err = ssha256.Generate(pass, 4); err != nil {
		t.Errorf("Generate password fails: %s", err)
		return
	}

	if res, err = ssha256.Validate(pass, hash); err != nil || res != true {
		t.Errorf("Generated hash can not be validated: %s", err)
	}
}

func TestGenerate8(t *testing.T) {
	pass := "test123"
	var hash string
	var err error
	var res bool

	if hash, err = ssha256.Generate(pass, 8); err != nil {
		t.Errorf("Generate password fails: %s", err)
		return
	}

	if res, err = ssha256.Validate(pass, hash); err != nil || res != true {
		t.Errorf("Generated hash can not be validated: %s", err)
	}
}

func TestGenerateManyPasses(t *testing.T) {
	pass := "foobar"
	var hash string
	var err error
	var res bool

	errors := 0

	for i := 0; i < 1000; i++ {
		if hash, err = ssha256.Generate(pass, 8); err != nil {
			t.Errorf("Generate password fails: %s", err)
			return
		}
	
		if res, err = ssha256.Validate(pass, hash); err != nil || res != true {
			t.Errorf("Generated hash can not be validated: %s", err)
			errors += 1
		}
	}

	if errors != 0 {
		t.Errorf("%d error(s) occurred when running 1000 passes", errors)
	}
}
