package memory

import (
	"context"
	"sync"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// AuditStore keeps audit entries in memory.
type AuditStore struct {
	mu      sync.RWMutex
	entries []domain.AuditEntry
}

// NewAuditStore returns an empty in-memory audit store.
func NewAuditStore() *AuditStore {
	return &AuditStore{entries: make([]domain.AuditEntry, 0)}
}

// Record stores a new audit entry.
func (s *AuditStore) Record(_ context.Context, entry domain.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, entry)
	return nil
}

// ListByOrg returns all audit entries matching orgID, or all if orgID is empty.
func (s *AuditStore) ListByOrg(_ context.Context, orgID string) ([]domain.AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []domain.AuditEntry
	for _, e := range s.entries {
		if orgID == "" || e.OrgID == orgID {
			result = append(result, e)
		}
	}
	return result, nil
}

// All returns a copy of all recorded audit entries.
func (s *AuditStore) All(_ context.Context) ([]domain.AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]domain.AuditEntry, len(s.entries))
	copy(result, s.entries)
	return result, nil
}
