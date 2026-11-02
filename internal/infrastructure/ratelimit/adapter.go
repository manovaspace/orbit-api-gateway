// Package ratelimit adapts the orbit-rate-limiting limiter (memory or Redis) to
// the domain rate-limit port.
package ratelimit

import (
	"context"

	ratelimiting "github.com/manovaspace/orbit-rate-limiting"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// Adapter implements domain.Limiter.
type Adapter struct {
	limiter ratelimiting.Limiter
}

// New wraps a limiter. A nil limiter yields a nil adapter, which the wiring
// treats as rate limiting disabled.
func New(limiter ratelimiting.Limiter) *Adapter {
	if limiter == nil {
		return nil
	}
	return &Adapter{limiter: limiter}
}

// Allow applies the policy to the key.
func (a *Adapter) Allow(ctx context.Context, key string, policy domain.Policy) (domain.Decision, error) {
	decision, err := a.limiter.Allow(ctx, key, toLibraryPolicy(policy))
	if err != nil {
		return domain.Decision{}, err
	}
	return domain.Decision{
		Allowed:    decision.Allowed,
		Limit:      decision.Limit,
		Remaining:  decision.Remaining,
		ResetAt:    decision.ResetAt,
		RetryAfter: decision.RetryAfter,
	}, nil
}

func toLibraryPolicy(policy domain.Policy) ratelimiting.Policy {
	return ratelimiting.Policy{Class: policy.Class, Limit: policy.Limit, Window: policy.Window}
}

// KeyForIP returns the per-IP, per-route bucket key from orbit-rate-limiting.
// An empty IP or route yields an empty key, which callers must not pass to the
// limiter.
func KeyForIP(ip, route string) string {
	return ratelimiting.KeyForIP(ip, route)
}

// KeyForOrg returns the per-organization, per-route bucket key from
// orbit-rate-limiting. An empty organization or route yields an empty key,
// which callers must not pass to the limiter.
func KeyForOrg(orgID, route string) string {
	return ratelimiting.KeyForOrg(orgID, route)
}
