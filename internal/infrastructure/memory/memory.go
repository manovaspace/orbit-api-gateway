// Package memory holds the in-memory adapters for the edge's two short-lived
// stores: ownership challenges and onboarding claims.
package memory

import (
	"context"
	"sync"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// Challenges keeps in-flight ownership challenges keyed by normalized email.
type Challenges struct {
	mu    sync.RWMutex
	items map[string]domain.Challenge
}

// NewChallenges returns an empty challenge store.
func NewChallenges() *Challenges {
	return &Challenges{items: make(map[string]domain.Challenge)}
}

// Save stores (or replaces) the challenge for email.
func (c *Challenges) Save(_ context.Context, email string, challenge domain.Challenge) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[email] = challenge
}

// Confirm atomically loads the challenge for email, removes it when accept
// returns true and reports whether it was removed. A rejected challenge stays
// stored, so a wrong code leaves the challenge usable.
func (c *Challenges) Confirm(_ context.Context, email string, accept func(domain.Challenge) bool) (domain.Challenge, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	challenge, ok := c.items[email]
	if !ok || !accept(challenge) {
		return domain.Challenge{}, false
	}
	delete(c.items, email)
	return challenge, true
}

// Claims keeps completed onboarding claims keyed by idempotency key.
type Claims struct {
	mu    sync.RWMutex
	items map[string]domain.ClaimResult
}

// NewClaims returns an empty claim cache.
func NewClaims() *Claims {
	return &Claims{items: make(map[string]domain.ClaimResult)}
}

// Get returns the cached claim for key.
func (c *Claims) Get(_ context.Context, key string) (domain.ClaimResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result, ok := c.items[key]
	return result, ok
}

// Put caches a completed claim.
func (c *Claims) Put(_ context.Context, key string, result domain.ClaimResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = result
}
