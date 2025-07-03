package errors

import (
	"errors"
	"strings"
	"testing"
)

func TestErrorHelpers(t *testing.T) {
	err := NewInvalidArgument("bad")
	if !IsInvalidArgument(err) {
		t.Fatal("expected invalid argument")
	}

	wrapped := WrapInternal(err, "ctx")
	if !IsInternal(wrapped) {
		t.Fatal("expected internal")
	}
}
func TestErrorChecks(t *testing.T) {
	cases := []struct {
		err   error
		check func(error) bool
	}{
		{ErrNotFound, IsNotFound},
		{ErrInvalidCredentials, IsInvalidCredentials},
		{ErrAlreadyExists, IsAlreadyExists},
		{ErrInvalidToken, IsInvalidToken},
		{ErrInvalidPassword, IsInvalidPassword},
		{ErrInvalidUsername, IsInvalidUsername},
	}
	for i, c := range cases {
		if !c.check(c.err) {
			t.Fatalf("case %d failed", i)
		}
		if c.check(nil) {
			t.Fatalf("nil check %d", i)
		}
	}
}

func TestWrapInternalKeepsMessage(t *testing.T) {
	src := errors.New("src")
	wrapped := WrapInternal(src, "context")
	if !IsInternal(wrapped) || !strings.Contains(wrapped.Error(), "context") {
		t.Fatal("wrap failed")
	}
}
