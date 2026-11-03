package application

import (
	"context"
	"testing"
	"time"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// fakeAuth records what the use cases send upstream and answers with the
// configured result.
type fakeAuth struct {
	requestOTP  func(domain.OTPRequest) (string, error)
	verifyOTP   func(domain.OTPVerification) (domain.TokenPair, error)
	login       func(domain.PasswordLogin) (domain.TokenPair, error)
	refresh     func(string) (domain.TokenPair, error)
	validate    func(string) (domain.APIIdentity, error)
	requestSeen []domain.OTPRequest
	loginSeen   []domain.PasswordLogin
	verifySeen  []domain.OTPVerification
	refreshSeen []string
}

func (f *fakeAuth) RequestOTP(_ context.Context, in domain.OTPRequest) (string, error) {
	f.requestSeen = append(f.requestSeen, in)
	if f.requestOTP != nil {
		return f.requestOTP(in)
	}
	return "2026-08-30T23:00:00Z", nil
}

func (f *fakeAuth) VerifyOTP(_ context.Context, in domain.OTPVerification) (domain.TokenPair, error) {
	f.verifySeen = append(f.verifySeen, in)
	if f.verifyOTP != nil {
		return f.verifyOTP(in)
	}
	return domain.TokenPair{AccessToken: "a", RefreshToken: "r", ExpiresAt: "e"}, nil
}

func (f *fakeAuth) LoginWithPassword(_ context.Context, in domain.PasswordLogin) (domain.TokenPair, error) {
	f.loginSeen = append(f.loginSeen, in)
	if f.login != nil {
		return f.login(in)
	}
	return domain.TokenPair{AccessToken: "a", RefreshToken: "r", ExpiresAt: "e"}, nil
}

func (f *fakeAuth) RefreshToken(_ context.Context, token string) (domain.TokenPair, error) {
	f.refreshSeen = append(f.refreshSeen, token)
	if f.refresh != nil {
		return f.refresh(token)
	}
	return domain.TokenPair{AccessToken: "a2", RefreshToken: "r2", ExpiresAt: "e"}, nil
}

func (f *fakeAuth) ValidateAPIToken(_ context.Context, secret string) (domain.APIIdentity, error) {
	if f.validate != nil {
		return f.validate(secret)
	}
	return domain.APIIdentity{UserID: "user", Scopes: []string{"read", "write"}}, nil
}

// fakeFlags answers the platform flag document.
type fakeFlags struct {
	set domain.FlagSet
	err error
}

func (f fakeFlags) ListFlags(context.Context) (domain.FlagSet, error) {
	return f.set, f.err
}

// fakeLimiter answers with one scripted decision and records every key and
// policy it was asked about.
type fakeLimiter struct {
	decision domain.Decision
	err      error
	keys     []string
	policies []domain.Policy
}

func (f *fakeLimiter) Allow(_ context.Context, key string, policy domain.Policy) (domain.Decision, error) {
	f.keys = append(f.keys, key)
	f.policies = append(f.policies, policy)
	if f.err != nil {
		return domain.Decision{}, f.err
	}
	return f.decision, nil
}

// fakeClock is a settable clock.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

// fakeCodes returns a fixed code.
type fakeCodes struct{ code string }

func (c fakeCodes) NewCode() string { return c.code }

// fakeChallenges is an in-memory challenge store with the same atomic
// compare-and-remove semantics as the production adapter.
type fakeChallenges struct{ items map[string]domain.Challenge }

func newFakeChallenges() *fakeChallenges {
	return &fakeChallenges{items: make(map[string]domain.Challenge)}
}

func (s *fakeChallenges) Save(_ context.Context, email string, challenge domain.Challenge) {
	s.items[email] = challenge
}

func (s *fakeChallenges) Confirm(_ context.Context, email string, accept func(domain.Challenge) bool) (domain.Challenge, bool) {
	challenge, ok := s.items[email]
	if !ok || !accept(challenge) {
		return domain.Challenge{}, false
	}
	delete(s.items, email)
	return challenge, true
}

// fakeClaims is an in-memory claim cache.
type fakeClaims struct{ items map[string]domain.ClaimResult }

func newFakeClaims() *fakeClaims { return &fakeClaims{items: make(map[string]domain.ClaimResult)} }

func (c *fakeClaims) Get(_ context.Context, key string) (domain.ClaimResult, bool) {
	result, ok := c.items[key]
	return result, ok
}

func (c *fakeClaims) Put(_ context.Context, key string, result domain.ClaimResult) {
	c.items[key] = result
}

// fakeAssets is a static asset set.
type fakeAssets struct {
	script   []byte
	specErr  error
	manifest []byte
}

func (a fakeAssets) InstallScript() []byte { return a.script }

func (a fakeAssets) OpenAPISpec() ([]byte, error) {
	if a.specErr != nil {
		return nil, a.specErr
	}
	return []byte("openapi: 3.1.0\n"), nil
}

func (a fakeAssets) Manifest() ([]byte, error) { return a.manifest, nil }

// testService builds a service with every port faked.
func testService(t *testing.T, mutate func(*Deps, *fakeAuth, *fakeLimiter)) (*Service, *fakeAuth, *fakeLimiter, *fakeChallenges, *fakeClaims) {
	t.Helper()
	auth := &fakeAuth{}
	limiter := &fakeLimiter{decision: domain.Decision{Allowed: true, Limit: 5, Remaining: 4}}
	challenges := newFakeChallenges()
	claims := newFakeClaims()
	deps := Deps{
		Auth:       auth,
		Flags:      fakeFlags{},
		Limiter:    limiter,
		Clock:      &fakeClock{now: testNow},
		Codes:      fakeCodes{code: "123456"},
		Challenges: challenges,
		Claims:     claims,
		Assets:     fakeAssets{script: []byte("#!/bin/sh\n"), manifest: []byte("{}\n")},
	}
	if mutate != nil {
		mutate(&deps, auth, limiter)
	}
	return NewService(deps), auth, limiter, challenges, claims
}

var testNow = time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
