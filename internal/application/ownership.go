package application

import (
	"context"
	"strings"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// ChallengeReceipt is a dispatched challenge plus the per-identifier budget it
// consumed, so the edge can render that bucket's headers.
type ChallengeReceipt struct {
	Grant           domain.ChallengeGrant
	IdentifierLimit *domain.Decision
}

// Challenge dispatches an ownership challenge. The code lives only in memory
// and is never mailed: the gateway holds no mailer.
func (s *Service) Challenge(ctx context.Context, email string) (ChallengeReceipt, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" || !strings.Contains(email, "@") {
		return ChallengeReceipt{}, domain.NewError(domain.KindInvalidArgument, "valid email is required")
	}
	limit, err := s.checkIdentifierLimit(ctx, email)
	if err != nil {
		return ChallengeReceipt{}, err
	}

	s.challenges.Save(ctx, email, domain.Challenge{
		Code:      s.codes.NewCode(),
		ExpiresAt: s.clock.Now().UTC().Add(domain.ChallengeTTL),
	})
	return ChallengeReceipt{
		Grant: domain.ChallengeGrant{
			Status:    domain.ChallengeStatusDispatched,
			ExpiresIn: domain.ChallengeExpiresIn,
		},
		IdentifierLimit: limit,
	}, nil
}

// VerifyChallenge checks a code once. A wrong code leaves the challenge in
// place, so a retry with the right code still succeeds.
func (s *Service) VerifyChallenge(ctx context.Context, email, code string) (domain.OwnershipProof, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	code = strings.TrimSpace(code)
	if email == "" || code == "" {
		return domain.OwnershipProof{}, domain.NewError(domain.KindInvalidArgument, "email and code are required")
	}

	now := s.clock.Now().UTC()
	if _, ok := s.challenges.Confirm(ctx, email, func(candidate domain.Challenge) bool {
		return candidate.Code == code && !now.After(candidate.ExpiresAt)
	}); !ok {
		return domain.OwnershipProof{}, domain.NewError(domain.KindUnauthenticated, "invalid or expired verification code")
	}

	return domain.OwnershipProof{
		Status:         domain.ProofStatusVerified,
		Email:          email,
		KeyFingerprint: domain.KeyFingerprint(email, code, now),
		VerifiedAt:     now,
	}, nil
}
