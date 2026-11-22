package domain

import (
	"testing"
	"time"
)

// The Google sign-in class is an edge class: 20 a minute per IP, reached through
// PolicyFor, and absent from the ADR-018 defaults the library mirrors.
func TestGoogleSignInPolicyIsTwentyAMinute(t *testing.T) {
	got := PolicyFor(ClassAuthGoogle)
	want := Policy{Class: ClassAuthGoogle, Limit: 20, Window: time.Minute}
	if got != want {
		t.Fatalf("PolicyFor(%q) = %+v, want %+v", ClassAuthGoogle, got, want)
	}
	if got != GoogleSignInPolicy() {
		t.Fatalf("PolicyFor and GoogleSignInPolicy disagree: %+v vs %+v", got, GoogleSignInPolicy())
	}
	if _, ok := DefaultAuthPolicies()[ClassAuthGoogle]; ok {
		t.Fatalf("%q must stay out of DefaultAuthPolicies", ClassAuthGoogle)
	}
}
