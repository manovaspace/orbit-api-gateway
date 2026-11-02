package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"

	ratelimiting "github.com/manovaspace/orbit-rate-limiting"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// TestDomainPoliciesMatchTheLibrary pins the copied policy values to
// orbit-rate-limiting, so a change there cannot silently drift the edge.
func TestDomainPoliciesMatchTheLibrary(t *testing.T) {
	library := ratelimiting.DefaultAuthPolicies()
	if len(domain.DefaultAuthPolicies()) != len(library) {
		t.Fatalf("domain has %d policies, the library %d", len(domain.DefaultAuthPolicies()), len(library))
	}
	for class := range library {
		got := toLibraryPolicy(domain.PolicyFor(class))
		if got != library[class] {
			t.Fatalf("policy %q = %+v, library %+v", class, got, library[class])
		}
	}
	if got, want := toLibraryPolicy(domain.OTPRequestIdentifierPolicy()), ratelimiting.OTPRequestIdentifierPolicy(); got != want {
		t.Fatalf("identifier policy = %+v, want %+v", got, want)
	}
}

type fixedLimiter struct {
	decision ratelimiting.Decision
	err      error
}

func (f fixedLimiter) Allow(context.Context, string, ratelimiting.Policy) (ratelimiting.Decision, error) {
	return f.decision, f.err
}

func TestAdapterMapsDecisions(t *testing.T) {
	reset := time.Unix(1_793_588_600, 0).UTC()
	adapter := New(fixedLimiter{decision: ratelimiting.Decision{
		Allowed: false, Limit: 5, Remaining: 0, ResetAt: reset, RetryAfter: 12 * time.Second,
	}})

	got, err := adapter.Allow(context.Background(), "key", domain.PolicyFor(domain.ClassAuthOTPRequest))
	if err != nil {
		t.Fatal(err)
	}
	want := domain.Decision{Allowed: false, Limit: 5, Remaining: 0, ResetAt: reset, RetryAfter: 12 * time.Second}
	if got != want {
		t.Fatalf("decision = %+v, want %+v", got, want)
	}
}

func TestAdapterPassesErrors(t *testing.T) {
	adapter := New(fixedLimiter{err: errors.New("redis down")})
	if _, err := adapter.Allow(context.Background(), "key", domain.Policy{}); err == nil {
		t.Fatal("the limiter error was swallowed")
	}
}

func TestNewWithNilIsNil(t *testing.T) {
	if New(nil) != nil {
		t.Fatal("New(nil) is not nil")
	}
}
