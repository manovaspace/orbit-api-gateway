package domain

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorKindsCarryTheirMessage(t *testing.T) {
	err := NewError(KindPermissionDenied, "no")
	if err.Error() != "no" {
		t.Fatalf("message = %q", err.Error())
	}
	wrapped := fmt.Errorf("wrap: %w", err)
	failure, ok := AsError(wrapped)
	if !ok || failure.Kind != KindPermissionDenied || failure.Message != "no" {
		t.Fatalf("AsError = %+v, %v", failure, ok)
	}
	if _, ok := AsError(errors.New("plain")); ok {
		t.Fatal("a plain error was read as a domain failure")
	}
}
