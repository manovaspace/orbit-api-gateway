package domain

import (
	"context"
	"time"
)

// AuditEntry records an administrative, tenant, or break-glass staff action.
type AuditEntry struct {
	ID         string         `json:"id"`
	OrgID      string         `json:"org_id"`
	Actor      string         `json:"actor"`
	ActorType  string         `json:"actor_type,omitempty"` // "user" | "staff"
	IsStaff    bool           `json:"is_staff"`
	BreakGlass bool           `json:"break_glass"`
	Reason     string         `json:"reason,omitempty"`
	Action     string         `json:"action"`
	Resource   string         `json:"resource"`
	Timestamp  time.Time      `json:"timestamp"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// AuditStore persists and queries audit entries.
type AuditStore interface {
	Record(ctx context.Context, entry AuditEntry) error
	ListByOrg(ctx context.Context, orgID string) ([]AuditEntry, error)
}
