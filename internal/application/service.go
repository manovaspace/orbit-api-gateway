// Package application implements the edge's use cases. It reads no environment
// variable and reaches the outside world only through the domain ports it
// receives in Deps.
package application

import "github.com/manovaspace/orbit-api-gateway/internal/domain"

// Deps are the service's ports and runtime collaborators.
type Deps struct {
	Auth       domain.AuthService
	Limiter    domain.Limiter
	Clock      domain.Clock
	Codes      domain.CodeGenerator
	Challenges domain.ChallengeStore
	Claims     domain.ClaimCache
	Assets     domain.Assets
	Logger     func(msg string, args ...any)
}

// Service orchestrates the auth, ownership and onboarding use cases.
type Service struct {
	auth       domain.AuthService
	limiter    domain.Limiter
	clock      domain.Clock
	codes      domain.CodeGenerator
	challenges domain.ChallengeStore
	claims     domain.ClaimCache
	assets     domain.Assets
	logger     func(msg string, args ...any)
}

// NewService builds the service from its ports.
func NewService(deps Deps) *Service {
	logger := deps.Logger
	if logger == nil {
		logger = func(string, ...any) {}
	}
	return &Service{
		auth:       deps.Auth,
		limiter:    deps.Limiter,
		clock:      deps.Clock,
		codes:      deps.Codes,
		challenges: deps.Challenges,
		claims:     deps.Claims,
		assets:     deps.Assets,
		logger:     logger,
	}
}

// HasAuth reports whether the upstream auth port is wired. Without it the edge
// does not register the auth routes, exactly as before.
func (s *Service) HasAuth() bool { return s.auth != nil }

// HasLimiter reports whether rate limiting is wired. Without it no route is
// wrapped and no rate-limit header is written.
func (s *Service) HasLimiter() bool { return s.limiter != nil }
