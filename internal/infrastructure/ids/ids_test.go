package ids

import (
	"regexp"
	"testing"
)

var sixDigits = regexp.MustCompile(`^\d{6}$`)

func TestNewCodeIsSixDigits(t *testing.T) {
	generator := New()
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		code := generator.NewCode()
		if !sixDigits.MatchString(code) {
			t.Fatalf("code %q is not six digits", code)
		}
		seen[code] = struct{}{}
	}
	// A constant generator would collapse the map; 1000 draws must not.
	if len(seen) < 100 {
		t.Fatalf("only %d distinct codes in 1000 draws", len(seen))
	}
}
