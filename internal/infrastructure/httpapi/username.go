package httpapi

import (
	"net/http"
)

// routeSessionUsername is the route template of the username route, and the
// rate-limit route name of its per-IP budget.
const routeSessionUsername = "/api/v1/session/username"

type sessionUsernameBody struct {
	Username string `json:"username"`
}

// setUsername sets the caller's username. The bearer token is required before the
// body is read, and is forwarded to orbit-auth, which takes the account from it.
func (h *handlers) setUsername(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireBearer(w, r)
	if !ok {
		return
	}
	var body sessionUsernameBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	username, err := h.svc.SetUsername(r.Context(), body.Username, token)
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": username})
}
