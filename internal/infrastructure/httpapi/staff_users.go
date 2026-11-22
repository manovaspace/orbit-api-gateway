package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// Route templates of the staff account and audit routes. They sit under
// /api/v1/staff and take a Keycloak staff token only; the staff reason of a write
// travels in the JSON body.
const (
	routeStaffUsers       = "/api/v1/staff/users"
	routeStaffUser        = "/api/v1/staff/users/{user_id}"
	routeStaffUserDisable = "/api/v1/staff/users/{user_id}/disable"
	routeStaffUserEnable  = "/api/v1/staff/users/{user_id}/enable"
	routeStaffAuditEvents = "/api/v1/staff/audit-events"
)

// staffReasonBody carries the audited reason of a staff write.
type staffReasonBody struct {
	Reason string `json:"reason"`
}

// staffUserJSON is an account as staff see it. Optional strings and times are
// omitted when absent.
type staffUserJSON struct {
	ID              string `json:"id"`
	Email           string `json:"email,omitempty"`
	Mobile          string `json:"mobile,omitempty"`
	Username        string `json:"username,omitempty"`
	DisplayName     string `json:"display_name,omitempty"`
	Status          string `json:"status"`
	EmailVerified   bool   `json:"email_verified"`
	MobileVerified  bool   `json:"mobile_verified"`
	HasPassword     bool   `json:"has_password"`
	GoogleLinked    bool   `json:"google_linked"`
	CreatedAt       string `json:"created_at"`
	LastLoginAt     string `json:"last_login_at,omitempty"`
	DisabledAt      string `json:"disabled_at,omitempty"`
	DisabledReason  string `json:"disabled_reason,omitempty"`
	MembershipCount int64  `json:"membership_count"`
}

type staffUserMembershipJSON struct {
	OrgID     string `json:"org_id"`
	OrgName   string `json:"org_name"`
	OrgSlug   string `json:"org_slug"`
	OrgStatus string `json:"org_status"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	JoinedAt  string `json:"joined_at"`
}

type staffUserDetailJSON struct {
	User        staffUserJSON             `json:"user"`
	Memberships []staffUserMembershipJSON `json:"memberships"`
}

type staffUserPageJSON struct {
	Users         []staffUserJSON `json:"users"`
	NextPageToken string          `json:"next_page_token"`
}

// staffAuditEventJSON is one audit row. Details is embedded as the JSON object
// the upstream stored; anything that is not a JSON object answers {}.
type staffAuditEventJSON struct {
	ID            int64           `json:"id"`
	OccurredAt    string          `json:"occurred_at"`
	Action        string          `json:"action"`
	ActorKind     string          `json:"actor_kind"`
	ActorID       string          `json:"actor_id,omitempty"`
	OrgID         string          `json:"org_id,omitempty"`
	SubjectUserID string          `json:"subject_user_id,omitempty"`
	InviteID      string          `json:"invite_id,omitempty"`
	Reason        string          `json:"reason,omitempty"`
	Details       json.RawMessage `json:"details"`
}

type staffAuditEventPageJSON struct {
	Events        []staffAuditEventJSON `json:"events"`
	NextPageToken string                `json:"next_page_token"`
}

// registerStaffUserRoutes mounts the staff account and audit routes. The caller
// registers them only when the staff OIDC verifier and the staff service token
// are both configured; otherwise the paths do not exist.
func (h *handlers) registerStaffUserRoutes(mux *http.ServeMux, ta *TokenAuth) {
	mux.Handle("GET "+routeStaffUsers, h.staffRoute(ta, routeStaffUsers, h.staffListUsers))
	mux.Handle("GET "+routeStaffUser, h.staffRoute(ta, routeStaffUser, h.staffGetUser))
	mux.Handle("POST "+routeStaffUserDisable, h.staffRoute(ta, routeStaffUserDisable, h.staffDisableUser))
	mux.Handle("POST "+routeStaffUserEnable, h.staffRoute(ta, routeStaffUserEnable, h.staffEnableUser))
	mux.Handle("GET "+routeStaffAuditEvents, h.staffRoute(ta, routeStaffAuditEvents, h.staffListAuditEvents))
}

func (h *handlers) staffListUsers(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	pageSize, ok := parsePageSize(w, query.Get("page_size"))
	if !ok {
		return
	}
	page, err := h.svc.ListStaffUsers(r.Context(), StaffSubjectFromContext(r.Context()), domain.StaffUserListRequest{
		Query:     strings.TrimSpace(query.Get("q")),
		Status:    strings.TrimSpace(query.Get("status")),
		PageToken: strings.TrimSpace(query.Get("page_token")),
		PageSize:  pageSize,
	})
	if err != nil {
		writeAppError(w, err)
		return
	}
	users := make([]staffUserJSON, 0, len(page.Users))
	for _, user := range page.Users {
		users = append(users, staffUserJSONFrom(user))
	}
	writeJSON(w, http.StatusOK, staffUserPageJSON{Users: users, NextPageToken: page.NextPageToken})
}

func (h *handlers) staffGetUser(w http.ResponseWriter, r *http.Request) {
	detail, err := h.svc.GetStaffUser(r.Context(), StaffSubjectFromContext(r.Context()), r.PathValue("user_id"))
	if err != nil {
		writeAppError(w, err)
		return
	}
	memberships := make([]staffUserMembershipJSON, 0, len(detail.Memberships))
	for _, m := range detail.Memberships {
		memberships = append(memberships, staffUserMembershipJSON{
			OrgID:     m.OrgID,
			OrgName:   m.OrgName,
			OrgSlug:   m.OrgSlug,
			OrgStatus: m.OrgStatus,
			Role:      m.Role,
			Status:    m.Status,
			JoinedAt:  m.JoinedAt,
		})
	}
	writeJSON(w, http.StatusOK, staffUserDetailJSON{User: staffUserJSONFrom(detail.User), Memberships: memberships})
}

func (h *handlers) staffDisableUser(w http.ResponseWriter, r *http.Request) {
	h.staffChangeUser(w, r, h.svc.DisableStaffUser)
}

func (h *handlers) staffEnableUser(w http.ResponseWriter, r *http.Request) {
	h.staffChangeUser(w, r, h.svc.EnableStaffUser)
}

// staffChangeUser runs one account write with the reason from the body and
// answers the account as it is afterwards.
func (h *handlers) staffChangeUser(w http.ResponseWriter, r *http.Request,
	change func(context.Context, domain.StaffActor, string) (domain.StaffUser, error)) {
	var body staffReasonBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	user, err := change(r.Context(), staffActor(r, body.Reason), r.PathValue("user_id"))
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, staffUserJSONFrom(user))
}

func (h *handlers) staffListAuditEvents(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	pageSize, ok := parsePageSize(w, query.Get("page_size"))
	if !ok {
		return
	}
	page, err := h.svc.ListStaffAuditEvents(r.Context(), StaffSubjectFromContext(r.Context()), domain.StaffAuditEventListRequest{
		OrgID:     strings.TrimSpace(query.Get("org_id")),
		UserID:    strings.TrimSpace(query.Get("user_id")),
		PageToken: strings.TrimSpace(query.Get("page_token")),
		PageSize:  pageSize,
	})
	if err != nil {
		writeAppError(w, err)
		return
	}
	events := make([]staffAuditEventJSON, 0, len(page.Events))
	for _, ev := range page.Events {
		events = append(events, staffAuditEventJSONFrom(ev))
	}
	writeJSON(w, http.StatusOK, staffAuditEventPageJSON{Events: events, NextPageToken: page.NextPageToken})
}

// parsePageSize reads an optional page_size query value. Empty means the upstream
// default; a value that is not an integer answers 400.
func parsePageSize(w http.ResponseWriter, raw string) (int32, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, true
	}
	n, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "page_size must be an integer"})
		return 0, false
	}
	return int32(n), true
}

func staffUserJSONFrom(user domain.StaffUser) staffUserJSON {
	return staffUserJSON{
		ID:              user.ID,
		Email:           user.Email,
		Mobile:          user.Mobile,
		Username:        user.Username,
		DisplayName:     user.DisplayName,
		Status:          user.Status,
		EmailVerified:   user.EmailVerified,
		MobileVerified:  user.MobileVerified,
		HasPassword:     user.HasPassword,
		GoogleLinked:    user.GoogleLinked,
		CreatedAt:       user.CreatedAt,
		LastLoginAt:     user.LastLoginAt,
		DisabledAt:      user.DisabledAt,
		DisabledReason:  user.DisabledReason,
		MembershipCount: user.MembershipCount,
	}
}

func staffAuditEventJSONFrom(ev domain.StaffAuditEvent) staffAuditEventJSON {
	details := json.RawMessage(`{}`)
	if json.Valid([]byte(ev.Details)) && strings.HasPrefix(strings.TrimSpace(ev.Details), "{") {
		details = json.RawMessage(ev.Details)
	}
	return staffAuditEventJSON{
		ID:            ev.ID,
		OccurredAt:    ev.OccurredAt,
		Action:        ev.Action,
		ActorKind:     ev.ActorKind,
		ActorID:       ev.ActorID,
		OrgID:         ev.OrgID,
		SubjectUserID: ev.SubjectUserID,
		InviteID:      ev.InviteID,
		Reason:        ev.Reason,
		Details:       details,
	}
}
