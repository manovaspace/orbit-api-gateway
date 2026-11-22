package httpapi

import (
	"net/http"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// Route templates of the Google sign-in routes. They are the paths the edge
// serves; the rate-limit class for both routes is domain.ClassAuthGoogle.
const (
	routeGoogleStart    = "/api/v1/auth/google/start"
	routeGoogleComplete = "/api/v1/auth/google/complete"
)

type googleStartBody struct {
	RedirectURI string `json:"redirect_uri"`
	ReturnTo    string `json:"return_to"`
	// InviteToken is optional. It is a bearer secret and is never logged.
	InviteToken string `json:"invite_token"`
}

type googleCompleteBody struct {
	State string `json:"state"`
	Code  string `json:"code"`
}

// googleStart asks orbit-auth for the browser redirect of a Google sign-in. The
// answer carries the single-use state, so it is never cacheable. Google off is a
// 404 from the adapter.
func (h *handlers) googleStart(w http.ResponseWriter, r *http.Request) {
	var body googleStartBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	started, err := h.svc.StartGoogleSignIn(r.Context(), domain.GoogleSignInStart{
		RedirectURI: body.RedirectURI,
		ReturnTo:    body.ReturnTo,
		InviteToken: body.InviteToken,
	})
	if err != nil {
		writeAppError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{
		"authorization_url": started.AuthorizationURL,
		"state":             started.State,
	})
}

// googleComplete exchanges the state and the authorization code for the same
// token envelope the other auth routes write, plus the return path. It is never
// cacheable.
func (h *handlers) googleComplete(w http.ResponseWriter, r *http.Request) {
	var body googleCompleteBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	completed, err := h.svc.CompleteGoogleSignIn(r.Context(), body.State, body.Code)
	if err != nil {
		writeAppError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, googleCompleteJSONFrom(completed))
}

// googleCompleteJSON is the completed sign-in. Fields are in alphabetical order,
// the order the original map encoder wrote them in. The invitation fields are
// added only for an invitation sign-in, and org_slug and role only when they
// are set, so a plain sign-in keeps its original body.
type googleCompleteJSON struct {
	AccessToken   string `json:"access_token"`
	AlreadyMember *bool  `json:"already_member,omitempty"`
	ExpiresAt     string `json:"expires_at"`
	InviteID      string `json:"invite_id,omitempty"`
	OrgID         string `json:"org_id,omitempty"`
	OrgSlug       string `json:"org_slug,omitempty"`
	RefreshToken  string `json:"refresh_token"`
	ReturnTo      string `json:"return_to"`
	Role          string `json:"role,omitempty"`
}

func googleCompleteJSONFrom(completed domain.GoogleSignInCompletion) googleCompleteJSON {
	body := googleCompleteJSON{
		AccessToken:  completed.Tokens.AccessToken,
		RefreshToken: completed.Tokens.RefreshToken,
		ExpiresAt:    completed.Tokens.ExpiresAt,
		ReturnTo:     completed.ReturnTo,
		InviteID:     completed.InviteID,
		OrgID:        completed.OrgID,
		OrgSlug:      completed.OrgSlug,
		Role:         completed.Role,
	}
	if completed.InviteID != "" {
		already := completed.AlreadyMember
		body.AlreadyMember = &already
	}
	return body
}
