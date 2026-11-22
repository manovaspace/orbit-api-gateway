package httpapi

import (
	"net/http"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// Route templates of the staff organization routes. They sit under /api/v1/staff
// and take a Keycloak staff token only; the staff reason travels in the JSON body
// of each write.
const (
	routeStaffOrgs         = "/api/v1/staff/orgs"
	routeStaffOrg          = "/api/v1/staff/orgs/{org_id}"
	routeStaffOwnerInvites = "/api/v1/staff/orgs/{org_id}/owner-invites"
)

type staffProvisionBody struct {
	Name           string `json:"name"`
	Slug           string `json:"slug"`
	OwnerEmail     string `json:"owner_email"`
	OwnerPhone     string `json:"owner_phone"`
	IdempotencyKey string `json:"idempotency_key"`
	AcceptURL      string `json:"accept_url"`
	Reason         string `json:"reason"`
}

type staffOwnerInviteBody struct {
	OwnerEmail string `json:"owner_email"`
	OwnerPhone string `json:"owner_phone"`
	AcceptURL  string `json:"accept_url"`
	Reason     string `json:"reason"`
}

type staffOrganizationJSON struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Slug         string   `json:"slug"`
	Status       string   `json:"status"`
	CreatedAt    string   `json:"created_at"`
	MemberCount  int64    `json:"member_count"`
	OwnerUserIDs []string `json:"owner_user_ids"`
}

type staffInviteJSON struct {
	ID        string `json:"id"`
	Email     string `json:"email,omitempty"`
	Phone     string `json:"phone,omitempty"`
	Role      string `json:"role"`
	ExpiresAt string `json:"expires_at"`
}

type staffMemberJSON struct {
	UserID   string `json:"user_id"`
	Role     string `json:"role"`
	Status   string `json:"status"`
	JoinedAt string `json:"joined_at"`
}

// staffProvisionedJSON answers a provisioning call. Token is set only for a phone
// owner, and only by this response.
type staffProvisionedJSON struct {
	Organization staffOrganizationJSON `json:"organization"`
	OwnerInvite  staffInviteJSON       `json:"owner_invite"`
	Token        string                `json:"token,omitempty"`
}

type staffOrgDetailJSON struct {
	Organization   staffOrganizationJSON `json:"organization"`
	Members        []staffMemberJSON     `json:"members"`
	PendingInvites []staffInviteJSON     `json:"pending_invites"`
}

// staffOwnerInviteJSON answers an owner invitation. Token is set only for a phone
// invitation, and only by this response.
type staffOwnerInviteJSON struct {
	Invite staffInviteJSON `json:"invite"`
	Token  string          `json:"token,omitempty"`
}

// registerStaffRoutes mounts the staff organization routes. The caller registers
// them only when the staff OIDC verifier and the staff service token are both
// configured; otherwise the paths do not exist.
func (h *handlers) registerStaffRoutes(mux *http.ServeMux, ta *TokenAuth) {
	mux.Handle("POST "+routeStaffOrgs, h.staffRoute(ta, routeStaffOrgs, h.staffProvisionOrg))
	mux.Handle("GET "+routeStaffOrg, h.staffRoute(ta, routeStaffOrg, h.staffGetOrg))
	mux.Handle("POST "+routeStaffOwnerInvites, h.staffRoute(ta, routeStaffOwnerInvites, h.staffReinviteOwner))
}

// staffRoute chains the staff checks: no-store on every answer, a Keycloak staff
// token only, then the per-staff-subject budget for the route.
func (h *handlers) staffRoute(ta *TokenAuth, route string, next http.HandlerFunc) http.Handler {
	return noStore(ta.RequireStaffOIDC(ta.StaffRateLimit(domain.StaffOrgRoutePolicy(route), next)))
}

// noStore marks every answer of the wrapped handler as uncacheable.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// staffActor takes the staff subject from the verified token and the reason from
// the body. The subject never comes from the request body.
func staffActor(r *http.Request, reason string) domain.StaffActor {
	return domain.StaffActor{Subject: StaffSubjectFromContext(r.Context()), Reason: reason}
}

func (h *handlers) staffProvisionOrg(w http.ResponseWriter, r *http.Request) {
	var body staffProvisionBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	provisioned, err := h.svc.ProvisionStaffOrg(r.Context(), staffActor(r, body.Reason), domain.StaffProvisionRequest{
		Name:           body.Name,
		Slug:           body.Slug,
		OwnerEmail:     body.OwnerEmail,
		OwnerPhone:     body.OwnerPhone,
		IdempotencyKey: body.IdempotencyKey,
		AcceptURL:      body.AcceptURL,
	})
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, staffProvisionedJSON{
		Organization: staffOrganizationJSONFrom(provisioned.Organization),
		OwnerInvite:  staffInviteJSONFrom(provisioned.OwnerInvite),
		Token:        provisioned.Token,
	})
}

func (h *handlers) staffGetOrg(w http.ResponseWriter, r *http.Request) {
	detail, err := h.svc.GetStaffOrg(r.Context(), StaffSubjectFromContext(r.Context()), r.PathValue("org_id"))
	if err != nil {
		writeAppError(w, err)
		return
	}
	members := make([]staffMemberJSON, 0, len(detail.Members))
	for _, member := range detail.Members {
		members = append(members, staffMemberJSON{UserID: member.UserID, Role: member.Role, Status: member.Status, JoinedAt: member.JoinedAt})
	}
	pending := make([]staffInviteJSON, 0, len(detail.PendingInvites))
	for _, invite := range detail.PendingInvites {
		pending = append(pending, staffInviteJSONFrom(invite))
	}
	writeJSON(w, http.StatusOK, staffOrgDetailJSON{
		Organization:   staffOrganizationJSONFrom(detail.Organization),
		Members:        members,
		PendingInvites: pending,
	})
}

func (h *handlers) staffReinviteOwner(w http.ResponseWriter, r *http.Request) {
	var body staffOwnerInviteBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	created, err := h.svc.ReinviteStaffOwner(r.Context(), staffActor(r, body.Reason), domain.StaffOwnerInviteRequest{
		OrgID:      r.PathValue("org_id"),
		OwnerEmail: body.OwnerEmail,
		OwnerPhone: body.OwnerPhone,
		AcceptURL:  body.AcceptURL,
	})
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, staffOwnerInviteJSON{Invite: staffInviteJSONFrom(created.Invite), Token: created.Token})
}

func staffOrganizationJSONFrom(org domain.StaffOrganization) staffOrganizationJSON {
	owners := org.OwnerUserIDs
	if owners == nil {
		owners = []string{}
	}
	return staffOrganizationJSON{
		ID:           org.ID,
		Name:         org.Name,
		Slug:         org.Slug,
		Status:       org.Status,
		CreatedAt:    org.CreatedAt,
		MemberCount:  org.MemberCount,
		OwnerUserIDs: owners,
	}
}

func staffInviteJSONFrom(invite domain.StaffInvite) staffInviteJSON {
	return staffInviteJSON{
		ID:        invite.ID,
		Email:     invite.Email,
		Phone:     invite.Phone,
		Role:      invite.Role,
		ExpiresAt: invite.ExpiresAt,
	}
}
