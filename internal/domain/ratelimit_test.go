package domain

import (
	"testing"
	"time"
)

func TestDefaultAuthPoliciesMatchTheAuthClasses(t *testing.T) {
	want := map[string]struct {
		limit  int
		window time.Duration
	}{
		ClassAuthOTPRequest: {5, time.Minute},
		ClassAuthOTPVerify:  {20, time.Minute},
		ClassAuthPassword:   {10, time.Minute},
		ClassAuthRefresh:    {30, time.Minute},
	}
	got := DefaultAuthPolicies()
	if len(got) != len(want) {
		t.Fatalf("policies = %v, want %d classes", got, len(want))
	}
	for class, expected := range want {
		policy, ok := got[class]
		if !ok {
			t.Fatalf("class %q has no policy", class)
		}
		if policy.Class != class || policy.Limit != expected.limit || policy.Window != expected.window {
			t.Fatalf("policy %q = %+v", class, policy)
		}
	}
}

func TestOTPRequestIdentifierPolicy(t *testing.T) {
	policy := OTPRequestIdentifierPolicy()
	if policy.Class != ClassAuthOTPRequest || policy.Limit != 3 || policy.Window != time.Minute {
		t.Fatalf("policy = %+v", policy)
	}
}

func TestPolicyForUnpolicedClassIsZero(t *testing.T) {
	for _, class := range []string{ClassOwnershipChallenge, ClassOwnershipVerify, ClassDevOnboardClaim, ClassAdminChallenge, ClassAdminVerify, ClassOnboardClaim, "unknown"} {
		if got := PolicyFor(class); got != (Policy{}) {
			t.Fatalf("PolicyFor(%q) = %+v, want the zero policy", class, got)
		}
	}
}

func TestRateLimitKeys(t *testing.T) {
	if got, want := ClientKey(ClassAuthPassword, "203.0.113.9"), "rl:auth_password:203.0.113.9"; got != want {
		t.Fatalf("ClientKey = %q, want %q", got, want)
	}
	if got, want := HashIdentifier(" limit@example.com "), "c0f2fc4762c66d47"; got != want {
		t.Fatalf("HashIdentifier = %q, want %q", got, want)
	}
	if got, want := IdentifierKey("limit@example.com"), "rl:auth_otp_request:id:"+HashIdentifier("limit@example.com"); got != want {
		t.Fatalf("IdentifierKey = %q, want %q", got, want)
	}
}

func TestLimitErrorMessages(t *testing.T) {
	if got := (&LimitError{}).Error(); got != "rate limit exceeded" {
		t.Fatalf("denied message = %q", got)
	}
	if got := (&LimitError{Unavailable: true}).Error(); got != "rate limiter unavailable" {
		t.Fatalf("unavailable message = %q", got)
	}
}
