package application

import (
	"context"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// ListFlags returns the platform flag document.
func (s *Service) ListFlags(ctx context.Context) (domain.FlagSet, error) {
	return s.flags.ListFlags(ctx)
}
