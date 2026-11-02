package application

import (
	"context"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// CheckClassLimit applies one route class policy to the calling client. The
// edge calls it before the handler; a denial returns *domain.LimitError with
// the decision so the response can carry the remaining budget.
func (s *Service) CheckClassLimit(ctx context.Context, class, clientIP string) (domain.Decision, error) {
	return s.allow(ctx, domain.ClientKey(class, clientIP), domain.PolicyFor(class))
}

// allow is the single place that turns limiter errors and denials into the
// failures the edge renders.
func (s *Service) allow(ctx context.Context, key string, policy domain.Policy) (domain.Decision, error) {
	decision, err := s.limiter.Allow(ctx, key, policy)
	if err != nil {
		return domain.Decision{}, &domain.LimitError{Unavailable: true}
	}
	if !decision.Allowed {
		return decision, &domain.LimitError{Decision: decision}
	}
	return decision, nil
}
