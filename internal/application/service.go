// Package application implements the edge's use cases. It reads no environment
// variable and reaches the outside world only through the domain ports it
// receives in Deps.
package application

import (
	"context"
	"fmt"
	"time"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// Deps are the service's ports and runtime collaborators.
type Deps struct {
	Auth       domain.AuthService
	Orgs       domain.OrgService
	StaffOrgs  domain.StaffOrgService
	StaffUsers domain.StaffUserService
	Accounts   domain.AccountService
	Signup     domain.SignupService
	Tenants    domain.TenantService
	Invites    domain.InviteService
	Google     domain.GoogleSignInService
	Usernames  domain.UsernameService
	Flags      domain.FlagSource
	Limiter    domain.Limiter
	Clock      domain.Clock
	Codes      domain.CodeGenerator
	Challenges domain.ChallengeStore
	Claims     domain.ClaimCache
	Assets     domain.Assets
	Audit      domain.AuditStore
	Logger     func(msg string, args ...any)
}

// Service orchestrates the auth, signup, organization, ownership and
// onboarding use cases.
type Service struct {
	auth       domain.AuthService
	orgs       domain.OrgService
	staffOrgs  domain.StaffOrgService
	staffUsers domain.StaffUserService
	accounts   domain.AccountService
	signup     domain.SignupService
	tenants    domain.TenantService
	invites    domain.InviteService
	google     domain.GoogleSignInService
	usernames  domain.UsernameService
	flags      domain.FlagSource
	limiter    domain.Limiter
	clock      domain.Clock
	codes      domain.CodeGenerator
	challenges domain.ChallengeStore
	claims     domain.ClaimCache
	assets     domain.Assets
	audit      domain.AuditStore
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
		orgs:       deps.Orgs,
		staffOrgs:  deps.StaffOrgs,
		staffUsers: deps.StaffUsers,
		accounts:   deps.Accounts,
		signup:     deps.Signup,
		tenants:    deps.Tenants,
		invites:    deps.Invites,
		google:     deps.Google,
		usernames:  deps.Usernames,
		flags:      deps.Flags,
		limiter:    deps.Limiter,
		clock:      deps.Clock,
		codes:      deps.Codes,
		challenges: deps.Challenges,
		claims:     deps.Claims,
		assets:     deps.Assets,
		audit:      deps.Audit,
		logger:     logger,
	}
}

// HasAuth reports whether the upstream auth port is wired. Without it the edge
// does not register the auth routes, exactly as before.
func (s *Service) HasAuth() bool { return s.auth != nil }

// HasOrgs reports whether the upstream organization port is wired.
func (s *Service) HasOrgs() bool { return s.orgs != nil }

// HasStaffOrgs reports whether the upstream staff organization port is wired. The
// edge wires it only when a staff service token is configured.
func (s *Service) HasStaffOrgs() bool { return s.staffOrgs != nil }

// HasStaffUsers reports whether the upstream staff account port is wired. The
// edge wires it only when a staff service token is configured.
func (s *Service) HasStaffUsers() bool { return s.staffUsers != nil }

// HasAccounts reports whether the account port is wired. The session sign-in
// method routes exist only when it is.
func (s *Service) HasAccounts() bool { return s.accounts != nil }

// HasTenants reports whether the upstream tenant-resolution port is wired.
func (s *Service) HasTenants() bool { return s.tenants != nil }

// HasSignup reports whether the upstream sign-up port is wired.
func (s *Service) HasSignup() bool { return s.signup != nil }

// HasInvites reports whether the public invitation port is wired. Without it the
// edge does not register the public invitation routes.
func (s *Service) HasInvites() bool { return s.invites != nil }

// HasGoogleSignIn reports whether the Google sign-in port is wired. Without it
// the edge does not register the Google sign-in routes.
func (s *Service) HasGoogleSignIn() bool { return s.google != nil }

// HasUsernames reports whether the username port is wired. Without it the edge
// does not register the username route.
func (s *Service) HasUsernames() bool { return s.usernames != nil }

// HasFlags reports whether the upstream flag source is wired.
func (s *Service) HasFlags() bool { return s.flags != nil }

// HasLimiter reports whether rate limiting is wired. Without it no route is
// wrapped and no rate-limit header is written.
func (s *Service) HasLimiter() bool { return s.limiter != nil }

// HasAudit reports whether an audit store is wired.
func (s *Service) HasAudit() bool { return s.audit != nil }

// RecordAudit persists an audit entry.
func (s *Service) RecordAudit(ctx context.Context, entry domain.AuditEntry) error {
	if s.audit == nil {
		return nil
	}
	if entry.Timestamp.IsZero() {
		if s.clock != nil {
			entry.Timestamp = s.clock.Now()
		} else {
			entry.Timestamp = time.Now()
		}
	}
	if entry.ID == "" {
		if s.codes != nil {
			entry.ID = fmt.Sprintf("audit-%s-%d", s.codes.NewCode(), entry.Timestamp.UnixNano())
		} else {
			entry.ID = fmt.Sprintf("audit-%d", entry.Timestamp.UnixNano())
		}
	}
	return s.audit.Record(ctx, entry)
}

// ListAuditEntries returns all audit entries for orgID.
func (s *Service) ListAuditEntries(ctx context.Context, orgID string) ([]domain.AuditEntry, error) {
	if s.audit == nil {
		return []domain.AuditEntry{}, nil
	}
	return s.audit.ListByOrg(ctx, orgID)
}

// AuditStore returns the wired domain.AuditStore.
func (s *Service) AuditStore() domain.AuditStore {
	return s.audit
}
