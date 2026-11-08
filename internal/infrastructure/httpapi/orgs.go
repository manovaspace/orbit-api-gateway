package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/ratelimit"
)

// Route templates are the rate-limit route names, so the bucket key names the
// documented template and never a concrete path with an organization id.
const (
	routeSignup                  = "/api/v1/auth/signup"
	routeSignupVerify            = "/api/v1/auth/signup/verify"
	routeOrgList                 = "/api/v1/orgs"
	routeOrgCreate               = "/api/v1/orgs"
	routeOrgMembers              = "/api/v1/orgs/{org_id}/members"
	routeOrgMemberRole           = "/api/v1/orgs/{org_id}/members/{user_id}/role"
	routeOrgSlug                 = "/api/v1/orgs/{org_id}/slug"
	routeTenantResolve           = "/api/v1/public/tenants/{slug}"
	routeOrgInvites              = "/api/v1/orgs/{org_id}/invites"
	routeOrgInviteRev            = "/api/v1/orgs/{org_id}/invites/{invite_id}"
	routeInviteAccept            = "/api/v1/invites/accept"
	routeSessionOrg              = "/api/v1/session/org"
	routeFlags                   = "/api/v1/flags"
	signupStatusVerificationSent = "verification_sent"
	revokeStatus                 = "revoked"
)

type signupBody struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	Locale      string `json:"locale"`
	OrgName     string `json:"org_name"`
	InviteToken string `json:"invite_token"`
}

type signupVerifyBody struct {
	Email    string `json:"email"`
	Code     string `json:"code"`
	Password string `json:"password"`
}

type createOrgBody struct {
	Name string `json:"name"`
	// Slug is optional: Orbit Auth derives one from the name when it is empty.
	Slug string `json:"slug"`
}

type setOrgSlugBody struct {
	Slug string `json:"slug"`
}

type tenantJSON struct {
	OrgID   string `json:"org_id"`
	Slug    string `json:"slug"`
	Name    string `json:"name"`
	Retired bool   `json:"retired"`
}

type addMemberBody struct {
	UserID string `json:"user_id"`
}

type setMemberRoleBody struct {
	Role string `json:"role"`
}

type membershipEnvelope struct {
	Membership membershipJSON `json:"membership"`
}

type inviteMemberBody struct {
	Email string `json:"email"`
}

type acceptInviteBody struct {
	Token string `json:"token"`
}

type selectOrgBody struct {
	OrgID        string `json:"org_id"`
	RefreshToken string `json:"refresh_token"`
}

type signupAcceptedResponse struct {
	Status string `json:"status"`
}

type organizationJSON struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type organizationEnvelope struct {
	Organization organizationJSON `json:"organization"`
}

type organizationList struct {
	Organizations []organizationJSON `json:"organizations"`
}

type membershipJSON struct {
	OrgID     string `json:"org_id"`
	UserID    string `json:"user_id"`
	Status    string `json:"status"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type membershipList struct {
	Members []membershipJSON `json:"members"`
}

type inviteJSON struct {
	ID         string `json:"id"`
	OrgID      string `json:"org_id"`
	Email      string `json:"email"`
	InviterID  string `json:"inviter_id"`
	Status     string `json:"status"`
	ExpiresAt  string `json:"expires_at"`
	AcceptedAt string `json:"accepted_at,omitempty"`
	CreatedAt  string `json:"created_at"`
}

type inviteEnvelope struct {
	Invite inviteJSON `json:"invite"`
}

type inviteList struct {
	Invites []inviteJSON `json:"invites"`
}

type revokeResponse struct {
	Status string `json:"status"`
}

// wrapIP applies the per-IP budget for a public route.
func (h *handlers) wrapIP(route string, limit int, next http.HandlerFunc) http.HandlerFunc {
	if !h.svc.HasLimiter() {
		return next
	}
	policy := domain.IPRoutePolicy(route, limit)
	return func(w http.ResponseWriter, r *http.Request) {
		key := ratelimit.KeyForIP(h.client.ip(r), route)
		h.applyRouteLimit(w, r, key, policy, next)
	}
}

// wrapOrg applies the rate limits for a route with an {org_id} path value. The
// order matters:
//
//  1. The per-IP budget is consumed before authentication, so one client cannot
//     flood orbit-auth with junk tokens.
//  2. The bearer token is required. A request without one gets 401 here and
//     never touches an organization bucket, so anonymous traffic cannot spend a
//     real administrator's budget.
//  3. The per-organization budget is keyed on the organization and a fingerprint
//     of the caller's token, so each caller has its own bucket.
//
// The handler runs only when all three allow the request.
func (h *handlers) wrapOrg(route string, next http.HandlerFunc) http.HandlerFunc {
	if !h.svc.HasLimiter() {
		return next
	}
	ipPolicy := domain.IPRoutePolicy(route, domain.OrgRouteIPLimit)
	orgPolicy := domain.OrgRoutePolicy(route)
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.consume(w, r, ratelimit.KeyForIP(h.client.ip(r), route), ipPolicy) {
			return
		}
		token, ok := h.requireBearer(w, r)
		if !ok {
			return
		}
		if !h.consume(w, r, orgCallerKey(r.PathValue("org_id"), token, route), orgPolicy) {
			return
		}
		next(w, r)
	}
}

// applyRouteLimit consumes one token and either continues or renders the
// denial.
func (h *handlers) applyRouteLimit(w http.ResponseWriter, r *http.Request, key string, policy domain.Policy, next http.HandlerFunc) {
	if !h.consume(w, r, key, policy) {
		return
	}
	next(w, r)
}

// consume takes one token from the bucket for key, writes the budget headers
// and reports whether the request may continue. On denial or limiter failure
// the response is already written and it returns false. An empty key is not
// addressable and is not passed to the limiter.
func (h *handlers) consume(w http.ResponseWriter, r *http.Request, key string, policy domain.Policy) bool {
	if key == "" {
		return true
	}
	decision, err := h.svc.CheckKeyLimit(r.Context(), key, policy)
	if err != nil {
		writeLimitError(w, err)
		return false
	}
	setRateLimitHeaders(w, decision)
	return true
}

// callerFingerprint returns the first 16 hex characters of the SHA-256 of the
// bearer token. The gateway does not verify the token, so the bucket is keyed
// on an unforgeable hash of it rather than on its unverified claims; a caller
// can only spend its own budget.
func callerFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:16]
}

// orgCallerKey is the per-organization, per-caller bucket key. It is empty when
// the organization id is blank, which the limiter never sees.
func orgCallerKey(orgID, token, route string) string {
	if strings.TrimSpace(orgID) == "" {
		return ""
	}
	return ratelimit.KeyForOrg(orgID+"/"+callerFingerprint(token), route)
}

// requireBearer extracts the access token the edge forwards to orbit-auth. The
// gateway does not verify it itself: orbit-auth's OrgService interceptor does.
func (h *handlers) requireBearer(w http.ResponseWriter, r *http.Request) (string, bool) {
	const prefix = "Bearer "
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, prefix) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(authorization, prefix))
	if token == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
		return "", false
	}
	return token, true
}

// checkOrgLimit applies the per-organization, per-caller budget when the
// organization id comes from the request body rather than the path. The caller
// is identified by its bearer token, so the caller must be authenticated first.
func (h *handlers) checkOrgLimit(w http.ResponseWriter, r *http.Request, orgID, token, route string) bool {
	if !h.svc.HasLimiter() {
		return true
	}
	return h.consume(w, r, orgCallerKey(orgID, token, route), domain.OrgRoutePolicy(route))
}

func (h *handlers) signup(w http.ResponseWriter, r *http.Request) {
	var body signupBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	err := h.svc.RegisterWithEmail(r.Context(), domain.SignupRegistration{
		Email:       body.Email,
		Password:    body.Password,
		DisplayName: body.DisplayName,
		Locale:      body.Locale,
		OrgName:     body.OrgName,
		InviteToken: body.InviteToken,
	})
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, signupAcceptedResponse{Status: signupStatusVerificationSent})
}

func (h *handlers) signupVerify(w http.ResponseWriter, r *http.Request) {
	var body signupVerifyBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	tokens, err := h.svc.VerifySignup(r.Context(), domain.SignupVerification{
		Email:    body.Email,
		Code:     body.Code,
		Password: body.Password,
	})
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeTokens(w, tokens)
}

func (h *handlers) listOrgs(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	orgs, err := h.svc.ListMyOrgs(r.Context(), token)
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, organizationList{Organizations: organizationsJSON(orgs)})
}

func (h *handlers) createOrg(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	var body createOrgBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	org, err := h.svc.CreateOrg(r.Context(), body.Name, strings.TrimSpace(body.Slug), token)
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, organizationEnvelope{Organization: organizationJSONFrom(org)})
}

func (h *handlers) setOrgSlug(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	var body setOrgSlugBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	org, err := h.svc.SetOrgSlug(r.Context(), r.PathValue("org_id"), strings.TrimSpace(body.Slug), token)
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, organizationEnvelope{Organization: organizationJSONFrom(org)})
}

// resolveTenant is public: the web edge calls it before anyone signs in, to map
// a tenant host label to an organization. It returns only the organization id,
// name and current slug. An answer is safe to cache briefly.
func (h *handlers) resolveTenant(w http.ResponseWriter, r *http.Request) {
	tenant, err := h.svc.ResolveTenant(r.Context(), strings.TrimSpace(r.PathValue("slug")))
	if err != nil {
		writeAppError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=30")
	writeJSON(w, http.StatusOK, tenantJSON{OrgID: tenant.OrgID, Slug: tenant.Slug, Name: tenant.Name, Retired: tenant.Retired})
}

func (h *handlers) listMembers(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	members, err := h.svc.ListMembers(r.Context(), r.PathValue("org_id"), token)
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, membershipList{Members: membershipsJSON(members)})
}

func (h *handlers) addMember(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	var body addMemberBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if err := h.svc.AddMember(r.Context(), r.PathValue("org_id"), body.UserID, token); err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, revokeResponse{Status: "added"})
}

func (h *handlers) removeMember(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	if err := h.svc.RemoveMember(r.Context(), r.PathValue("org_id"), r.PathValue("user_id"), token); err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, revokeResponse{Status: "removed"})
}

func (h *handlers) suspendMember(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	if err := h.svc.SuspendMember(r.Context(), r.PathValue("org_id"), r.PathValue("user_id"), token); err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, revokeResponse{Status: "suspended"})
}

func (h *handlers) setMemberRole(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	var body setMemberRoleBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	member, err := h.svc.SetMemberRole(r.Context(), r.PathValue("org_id"), r.PathValue("user_id"), strings.TrimSpace(body.Role), token)
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, membershipEnvelope{Membership: membershipJSONFrom(member)})
}

func (h *handlers) createInvite(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	var body inviteMemberBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	invite, err := h.svc.InviteMember(r.Context(), r.PathValue("org_id"), body.Email, token)
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, inviteEnvelope{Invite: inviteJSONFrom(invite)})
}

func (h *handlers) listInvites(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	invites, err := h.svc.ListInvites(r.Context(), r.PathValue("org_id"), token)
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, inviteList{Invites: invitesJSON(invites)})
}

func (h *handlers) revokeInvite(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	if err := h.svc.RevokeInvite(r.Context(), r.PathValue("org_id"), r.PathValue("invite_id"), token); err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, revokeResponse{Status: revokeStatus})
}

func (h *handlers) acceptInvite(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	var body acceptInviteBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	invite, err := h.svc.AcceptInvite(r.Context(), body.Token, token)
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, inviteEnvelope{Invite: inviteJSONFrom(invite)})
}

func (h *handlers) selectOrg(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	var body selectOrgBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if !h.checkOrgLimit(w, r, body.OrgID, token, routeSessionOrg) {
		return
	}
	tokens, err := h.svc.SelectOrg(r.Context(), body.OrgID, body.RefreshToken, token)
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeTokens(w, tokens)
}

func organizationJSONFrom(org domain.Organization) organizationJSON {
	return organizationJSON{
		ID:        org.ID,
		Name:      org.Name,
		Slug:      org.Slug,
		CreatedAt: org.CreatedAt,
		UpdatedAt: org.UpdatedAt,
	}
}

func organizationsJSON(orgs []domain.Organization) []organizationJSON {
	out := make([]organizationJSON, 0, len(orgs))
	for _, org := range orgs {
		out = append(out, organizationJSONFrom(org))
	}
	return out
}

func membershipJSONFrom(member domain.Membership) membershipJSON {
	return membershipJSON{
		OrgID:     member.OrgID,
		UserID:    member.UserID,
		Status:    member.Status,
		Role:      member.Role,
		CreatedAt: member.CreatedAt,
		UpdatedAt: member.UpdatedAt,
	}
}

func membershipsJSON(members []domain.Membership) []membershipJSON {
	out := make([]membershipJSON, 0, len(members))
	for _, member := range members {
		out = append(out, membershipJSONFrom(member))
	}
	return out
}

func inviteJSONFrom(invite domain.Invite) inviteJSON {
	return inviteJSON{
		ID:         invite.ID,
		OrgID:      invite.OrgID,
		Email:      invite.Email,
		InviterID:  invite.InviterID,
		Status:     invite.Status,
		ExpiresAt:  invite.ExpiresAt,
		AcceptedAt: invite.AcceptedAt,
		CreatedAt:  invite.CreatedAt,
	}
}

func invitesJSON(invites []domain.Invite) []inviteJSON {
	out := make([]inviteJSON, 0, len(invites))
	for _, invite := range invites {
		out = append(out, inviteJSONFrom(invite))
	}
	return out
}
