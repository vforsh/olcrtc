package diagnostic

import (
	"errors"
	"fmt"
	"testing"
)

// ai-generated: verify categories survive ordinary Go error wrapping.
func TestCategoryOfWrappedError(t *testing.T) {
	sentinel := errors.New("boom")
	err := fmt.Errorf("outer: %w", Wrap(CategoryHandshake, sentinel))
	if got := CategoryOf(err); got != CategoryHandshake {
		t.Fatalf("CategoryOf() = %q, want %q", got, CategoryHandshake)
	}
	if !errors.Is(err, sentinel) {
		t.Fatal("categorized error does not preserve errors.Is")
	}
}

// ai-generated: keep untyped errors in the stable runtime fallback bucket.
func TestCategoryOfUntypedError(t *testing.T) {
	if got := CategoryOf(errors.New("boom")); got != CategoryRuntime {
		t.Fatalf("CategoryOf() = %q, want %q", got, CategoryRuntime)
	}
}
