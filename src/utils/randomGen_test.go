package utils

import (
	"testing"
)

func TestGen32(t *testing.T) {
	s := Gen32()
	if len(s) != 32 {
		t.Errorf("the length of the random generated string is %d", len(s))
	}
}
