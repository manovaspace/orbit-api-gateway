package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// Route templates of the bearer session routes. Each one takes the caller's
// access token and acts only on its subject. None of them logs its body, its
// query or its token: the passwords, the refresh token, the Google code and
// state are secrets.
const (
	routeSessionSignInMethods   = "/api/v1/session/sign-in-methods"
	routeSessionPassword        = "/api/v1/session/password"
	routeSessionGoogleLinkStart = "/api/v1/session/google/link/start"
	routeSessionGoogleLinkDone  = "/api/v1/session/google/link/complete"
	routeSessionGoogle          = "/api/v1/session/google"
	routeSessionRevokeAll       = "/api/v1/session/revoke-all"
)

// googleLinkJSON is the linked Google account. The timestamps are null until
// they are set.
type googleLinkJSON struct {
	Email       string  `json:"email"`
	LastLoginAt *string `json:"last_login_at"`
	LinkedAt    *string `json:"linked_at"`
}

// signInMethodsJSON is the sign-in methods of the caller. The optional strings
// are null when the account has none, the shape product settings pages read.
type signInMethodsJSON struct {
	Email          *string          `json:"email"`
	EmailVerified  bool             `json:"email_verified"`
	Google         []googleLinkJSON `json:"google"`
	HasPassword    bool             `json:"has_password"`
	Mobile         *string          `json:"mobile"`
	MobileVerified bool             `json:"mobile_verified"`
	Username       *string          `json:"username"`
}

type setPasswordBody struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	RefreshToken    string `json:"refresh_token"`
}

type googleLinkStartBody struct {
	RedirectURI string `json:"redirect_uri"`
	ReturnTo    string `json:"return_to"`
}

type googleLinkCompleteBody struct {
	State string `json:"state"`
	Code  string `json:"code"`
}

type revokeAllBody struct {
	RefreshToken string `json:"refresh_token"`
}

// signInMethods returns how the caller's account signs in.
func (h *handlers) signInMethods(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	methods, err := h.svc.GetSignInMethods(r.Context(), token)
	if err != nil {
		writeAppError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, signInMethodsJSONFrom(methods))
}

// setPassword sets or changes the caller's password. Orbit-auth first answers a
// read with the same token, so the subject of the budget is proven and a forged
// token cannot spend the budget of another account. The budget is consumed before
// orbit-auth sees the password, so a wrong current password counts against it.
func (h *handlers) setPassword(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	var body setPasswordBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if _, err := h.svc.GetSignInMethods(r.Context(), token); err != nil {
		writeAppError(w, err)
		return
	}
	if !h.consumePasswordBudget(w, r, token) {
		return
	}
	err := h.svc.SetPassword(r.Context(), domain.SetPasswordRequest{
		CurrentPassword: body.CurrentPassword,
		NewPassword:     body.NewPassword,
		RefreshToken:    body.RefreshToken,
	}, token)
	if err != nil {
		writeAppError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// startGoogleLink begins linking a Google account to the caller. The answer
// carries the single-use state, so it is never cacheable.
func (h *handlers) startGoogleLink(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	var body googleLinkStartBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	started, err := h.svc.StartGoogleLink(r.Context(), domain.GoogleLinkStart{
		RedirectURI: body.RedirectURI,
		ReturnTo:    body.ReturnTo,
	}, token)
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

// completeGoogleLink finishes a Google link. It issues no tokens.
func (h *handlers) completeGoogleLink(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	var body googleLinkCompleteBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	linked, err := h.svc.CompleteGoogleLink(r.Context(), domain.GoogleLinkComplete{
		State: body.State,
		Code:  body.Code,
	}, token)
	if err != nil {
		writeAppError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{
		"email":     linked.Email,
		"return_to": linked.ReturnTo,
	})
}

// unlinkGoogle removes the Google account from the caller.
func (h *handlers) unlinkGoogle(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	if err := h.svc.UnlinkGoogle(r.Context(), token); err != nil {
		writeAppError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// revokeAllSessions ends the caller's sessions. The refresh token, when given,
// names the one session to keep.
func (h *handlers) revokeAllSessions(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	var body revokeAllBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if err := h.svc.RevokeAllSessions(r.Context(), body.RefreshToken, token); err != nil {
		writeAppError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// consumePasswordBudget takes one token from the per-subject password budget.
// The gateway does not verify orbit-auth tokens itself, so the caller must have
// had the token accepted by orbit-auth before it reads the sub claim here. A
// token with no readable sub is bucketed on its fingerprint.
func (h *handlers) consumePasswordBudget(w http.ResponseWriter, r *http.Request, token string) bool {
	if !h.svc.HasLimiter() {
		return true
	}
	subject := unverifiedSubject(token)
	if subject == "" {
		subject = "token:" + callerFingerprint(token)
	}
	return h.consume(w, r, domain.SubjectKey(domain.ClassSessionPassword, subject), domain.SessionPasswordPolicy())
}

// unverifiedSubject reads the sub claim of a JWT without verifying it. It is used
// only to choose a rate-limit bucket, never to authorize anything. It returns
// empty when the token is not a readable JWT.
func unverifiedSubject(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return ""
	}
	return strings.TrimSpace(claims.Sub)
}

// nullableString maps an empty string to null.
func nullableString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func signInMethodsJSONFrom(methods domain.SignInMethods) signInMethodsJSON {
	google := make([]googleLinkJSON, 0, len(methods.Google))
	for _, link := range methods.Google {
		google = append(google, googleLinkJSON{
			Email:       link.Email,
			LastLoginAt: nullableString(link.LastLoginAt),
			LinkedAt:    nullableString(link.LinkedAt),
		})
	}
	return signInMethodsJSON{
		Email:          nullableString(methods.Email),
		EmailVerified:  methods.EmailVerified,
		Google:         google,
		HasPassword:    methods.HasPassword,
		Mobile:         nullableString(methods.Mobile),
		MobileVerified: methods.MobileVerified,
		Username:       nullableString(methods.Username),
	}
}
