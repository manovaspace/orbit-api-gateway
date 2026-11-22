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
	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  completed.Tokens.AccessToken,
		"refresh_token": completed.Tokens.RefreshToken,
		"expires_at":    completed.Tokens.ExpiresAt,
		"return_to":     completed.ReturnTo,
	})
}
