package errors

import "testing"

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
