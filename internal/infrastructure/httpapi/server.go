// Package httpapi serves the REST edge on Fiber v3. The routes run on the same
// net/http handlers the service used before the migration, adapted unchanged,
// so routing, status codes, headers and bodies stay identical. The contract in
// contract_test.go pins that: its assertions passed against the net/http server
// first and were not edited for Fiber.
package httpapi

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"

	observability "github.com/manovaspace/orbit-observability"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// Server wraps the Fiber app so main only starts and stops it.
type Server struct {
	app         *fiber.App
	mux         *http.ServeMux
	svc         *application.Service
	jwtSecret   string
	staffSecret string
}

// Options configure the edge.
type Options struct {
	// TrustProxy makes the edge read the client address from X-Forwarded-For.
	TrustProxy bool
	// JWTSecret is the HS256 secret for the token middleware a deployment
	// binary mounts. Empty makes that middleware fail closed.
	JWTSecret string
	// StaffSecret is the secret for staff credentials. Defaults to JWTSecret when empty.
	StaffSecret string
}

// New builds the platform REST edge (auth + ownership + onboarding + OpenAPI).
// Product backends mount additional routes in their deployment binary or in an
// edge reverse proxy; this binary still does not proxy them.
func New(svc *application.Service, opts Options) *Server {
	h := &handlers{svc: svc, trustProxy: opts.TrustProxy}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.health)
	wrap := h.wrap

	// Global Identity & Auth.
	if svc.HasAuth() {
		mux.HandleFunc("POST /api/v1/auth/otp/request", wrap(domain.ClassAuthOTPRequest, h.requestOTP))
		mux.HandleFunc("POST /api/v1/auth/otp/verify", wrap(domain.ClassAuthOTPVerify, h.verifyOTP))
		mux.HandleFunc("POST /api/v1/auth/login", wrap(domain.ClassAuthPassword, h.login))
		mux.HandleFunc("POST /api/v1/auth/token/refresh", wrap(domain.ClassAuthRefresh, h.refreshToken))
	}

	// Self-serve sign-up (unauthenticated, strict per-IP budget).
	if svc.HasSignup() {
		mux.HandleFunc("POST /api/v1/auth/signup", h.wrapIP(routeSignup, domain.SignupIPLimit, h.signup))
		mux.HandleFunc("POST /api/v1/auth/signup/verify", h.wrapIP(routeSignupVerify, domain.SignupIPLimit, h.signupVerify))
	}

	// Platform feature flags (unauthenticated, public per-IP budget). Browsers
	// read these before sign-in.
	if svc.HasFlags() {
		mux.HandleFunc("GET "+routeFlags, h.wrapIP(routeFlags, domain.OrgRouteLimit, h.flags))
	}

	// Organizations and invitations. Every call carries the caller's bearer
	// token to orbit-auth; organization-scoped routes use a per-org budget.
	if svc.HasOrgs() {
		// Listing and creating have no organization id to bucket on yet, so
		// they use the per-IP key with the organization budget.
		mux.HandleFunc("GET /api/v1/orgs", h.wrapIP(routeOrgList, domain.OrgRouteLimit, h.listOrgs))
		mux.HandleFunc("POST /api/v1/orgs", h.wrapIP(routeOrgCreate, domain.OrgRouteLimit, h.createOrg))
		mux.HandleFunc("GET /api/v1/orgs/{org_id}/members", h.wrapOrg(routeOrgMembers, h.listMembers))
		mux.HandleFunc("POST /api/v1/orgs/{org_id}/members", h.wrapOrg(routeOrgMembers, h.addMember))
		mux.HandleFunc("DELETE /api/v1/orgs/{org_id}/members/{user_id}", h.wrapOrg(routeOrgMembers, h.removeMember))
		mux.HandleFunc("POST /api/v1/orgs/{org_id}/members/{user_id}/suspend", h.wrapOrg(routeOrgMembers, h.suspendMember))
		mux.HandleFunc("POST /api/v1/orgs/{org_id}/invites", h.wrapOrg(routeOrgInvites, h.createInvite))
		mux.HandleFunc("GET /api/v1/orgs/{org_id}/invites", h.wrapOrg(routeOrgInvites, h.listInvites))
		mux.HandleFunc("DELETE /api/v1/orgs/{org_id}/invites/{invite_id}", h.wrapOrg(routeOrgInviteRev, h.revokeInvite))
		mux.HandleFunc("POST /api/v1/invites/accept", h.wrapIP(routeInviteAccept, domain.InviteAcceptIPLimit, h.acceptInvite))
		mux.HandleFunc("POST /api/v1/session/org", h.selectOrg)
	}

	// Canonical System & Infrastructure Plane (Platform Ownership).
	mux.HandleFunc("POST /api/v1/system/ownership/challenge", wrap(domain.ClassOwnershipChallenge, h.challenge))
	mux.HandleFunc("POST /api/v1/system/ownership/verify", wrap(domain.ClassOwnershipVerify, h.verifyChallenge))

	// Canonical Developer Experience Plane (Workstation Provisioning).
	mux.HandleFunc("POST /api/v1/dev/onboard/claim", wrap(domain.ClassDevOnboardClaim, h.claim))

	// Backward-Compatible Aliases.
	mux.HandleFunc("POST /api/v1/admin/challenge", wrap(domain.ClassAdminChallenge, h.challenge))
	mux.HandleFunc("POST /api/v1/admin/verify", wrap(domain.ClassAdminVerify, h.verifyChallenge))
	mux.HandleFunc("POST /api/v1/onboard/claim", wrap(domain.ClassOnboardClaim, h.claim))
	mux.HandleFunc("POST /v1/onboard/claim", wrap(domain.ClassOnboardClaim, h.claim))

	// Canonical Installer.
	mux.HandleFunc("GET /", h.install)

	registerOpenAPIRoutes(mux, svc)

	server := newServer(observability.HTTPMiddleware(mux), mux)
	server.svc = svc
	server.jwtSecret = opts.JWTSecret
	server.staffSecret = opts.StaffSecret
	return server
}

// NewHealth builds the dedicated health server: /healthz and /readyz only, on
// the same handlers and middleware the previous net/http server used.
func NewHealth() *Server {
	mux := http.NewServeMux()
	mux.Handle("/healthz", observability.HealthHandler())
	mux.Handle("/readyz", observability.ReadinessHandler())
	return newServer(observability.HTTPMiddleware(mux), mux)
}

// newServer fronts an http.Handler chain with Fiber v3. The routes stay on the
// net/http mux so the mux's own routing, 405 Allow headers and 404 bodies are
// preserved instead of Fiber's defaults.
func newServer(handler http.Handler, mux *http.ServeMux) *Server {
	app := fiber.New(fiber.Config{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		// The edge caps JSON bodies at maxAuthBody in the handlers. This limit
		// only bounds what the HTTP front buffers before the handler sees the
		// body; it must stay well above maxAuthBody so the documented cap is
		// the one that answers.
		BodyLimit: 4 << 20,
	})
	// The service logs its own JSON startup lines through observability.
	app.Hooks().OnPreStartupMessage(func(data *fiber.PreStartupMessageData) error {
		data.PreventDefault = true
		return nil
	})
	// Every handler sets its Content-Type. Keep fasthttp from inventing one for
	// a response that has none, so the header set matches the net/http server.
	app.Use(func(c fiber.Ctx) error {
		c.Response().Header.SetNoDefaultContentType(true)
		return c.Next()
	})
	// fasthttp canonicalises response header keys, so "X-RateLimit-Limit"
	// becomes "X-Ratelimit-Limit". Header names are case-insensitive, but the
	// bytes are part of the published shape, so restore them. SetCanonical
	// stores the key verbatim; the price is that fasthttp's own Peek/Get
	// canonicalise their argument and no longer find these three keys. Nothing
	// in this service reads them back; use VisitAll if that ever changes.
	app.Use(func(c fiber.Ctx) error {
		err := c.Next()
		header := &c.Response().Header
		for _, spelling := range rateLimitHeaderSpellings {
			value := header.Peek(spelling[0])
			if len(value) == 0 {
				continue
			}
			header.Del(spelling[0])
			header.SetCanonical([]byte(spelling[1]), value)
		}
		return err
	})
	app.Use(adaptor.HTTPHandler(handler))
	return &Server{app: app, mux: mux}
}

// rateLimitHeaderSpellings maps the key fasthttp stores to the key the edge has
// always published.
var rateLimitHeaderSpellings = [][2]string{
	{"X-Ratelimit-Limit", "X-RateLimit-Limit"},
	{"X-Ratelimit-Remaining", "X-RateLimit-Remaining"},
	{"X-Ratelimit-Reset", "X-RateLimit-Reset"},
}

// TokenAuth returns the bearer-token middleware for the routes a deployment
// binary mounts. The platform binary mounts none of them.
func (s *Server) TokenAuth() *TokenAuth {
	ta := NewTokenAuth(s.svc, s.jwtSecret)
	if s.staffSecret != "" {
		ta.WithStaffSecret(s.staffSecret)
	}
	return ta
}

// StaffAuth returns the staff auth middleware.
func (s *Server) StaffAuth() *StaffAuth {
	return NewStaffAuth(s.TokenAuth())
}

// ServeJWKS publishes a precomputed JWK set document at
// GET /.well-known/jwks.json so product APIs can verify Orbit Auth tokens.
func (s *Server) ServeJWKS(body []byte) {
	s.mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	})
}

// Listen serves HTTP on addr until Shutdown is called.
func (s *Server) Listen(addr string) error {
	return s.app.Listen(addr)
}

// Shutdown drains the HTTP server within ctx.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.app.ShutdownWithContext(ctx)
}

// serve serves on an existing listener. Tests use it to bind an ephemeral port.
func (s *Server) serve(ln net.Listener) error {
	return s.app.Listener(ln)
}
