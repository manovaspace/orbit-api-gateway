package httpapi

import (
	"net/http"
	"strings"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// Route templates of the public invitation routes. They carry no path parameter:
// the invitation token travels in the JSON body, never in the URL, because a URL
// reaches trace attributes (url.path) and proxy access logs, and a body does not.
const (
	routeInvitePreview      = "/api/v1/public/invites/preview"
	routeInviteSignupAccept = "/api/v1/public/invites/accept"
)

// The invitation token is a bearer secret. It is never logged, it is never part of
// a rate-limit key, and it is removed from any error message before the message
// reaches a response body.

// publicInviteRoute is one public invitation route: its method and template, the
// per-IP budget it spends and its handler.
type publicInviteRoute struct {
	method   string
	template string
	budget   int
	handler  http.HandlerFunc
}

// publicInviteRoutes is the route table of the public invitation routes. New
// registers exactly this table, so the tests check the routes the edge serves.
func (h *handlers) publicInviteRoutes() []publicInviteRoute {
	return []publicInviteRoute{
		{method: http.MethodPost, template: routeInvitePreview, budget: domain.InvitePreviewIPLimit, handler: h.invitePreview},
		{method: http.MethodPost, template: routeInviteSignupAccept, budget: domain.InviteSignupAcceptIPLimit, handler: h.inviteSignupAccept},
	}
}

type inviteTokenBody struct {
	Token string `json:"token"`
}

type inviteSignupBody struct {
	Token       string `json:"token"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

type invitePreviewJSON struct {
	OrgID     string `json:"org_id"`
	OrgName   string `json:"org_name"`
	OrgSlug   string `json:"org_slug"`
	Role      string `json:"role"`
	ExpiresAt string `json:"expires_at"`
}

type inviteSignupJSON struct {
	UserID string `json:"user_id"`
	OrgID  string `json:"org_id"`
}

// invitePreview shows what an invitation grants before sign-in. It never returns
// the recipient, and it is never cacheable.
func (h *handlers) invitePreview(w http.ResponseWriter, r *http.Request) {
	var body inviteTokenBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	token := strings.TrimSpace(body.Token)
	if token == "" {
		writeAppError(w, domain.NewError(domain.KindInvalidArgument, "token is required"))
		return
	}
	preview, err := h.svc.GetInvitePreview(r.Context(), token)
	if err != nil {
		writeInviteError(w, token, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, invitePreviewJSON{
		OrgID:     preview.OrgID,
		OrgName:   preview.OrgName,
		OrgSlug:   preview.OrgSlug,
		Role:      preview.Role,
		ExpiresAt: preview.ExpiresAt,
	})
}

// inviteSignupAccept creates the account for a phone invitation, sets its password
// and display name, and joins the organization with the invited tier.
func (h *handlers) inviteSignupAccept(w http.ResponseWriter, r *http.Request) {
	var body inviteSignupBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	token := strings.TrimSpace(body.Token)
	if token == "" {
		writeAppError(w, domain.NewError(domain.KindInvalidArgument, "token is required"))
		return
	}
	accepted, err := h.svc.AcceptInviteWithSignup(r.Context(), domain.InviteSignup{
		Token:       token,
		Password:    body.Password,
		DisplayName: body.DisplayName,
	})
	if err != nil {
		writeInviteError(w, token, err)
		return
	}
	writeJSON(w, http.StatusCreated, inviteSignupJSON{UserID: accepted.UserID, OrgID: accepted.OrgID})
}

// writeInviteError renders a failure of a public invitation route. A message that
// contains the token has the token replaced before it is written.
func writeInviteError(w http.ResponseWriter, token string, err error) {
	if failure, ok := domain.AsError(err); ok && token != "" && strings.Contains(failure.Message, token) {
		err = domain.NewError(failure.Kind, strings.ReplaceAll(failure.Message, token, "[redacted]"))
	}
	writeAppError(w, err)
}
