package httpapi

import (
	_ "embed"
	"net/http"

	observability "github.com/manovaspace/orbit-observability"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

//go:embed install.sh
var canonicalInstallScript []byte

type Server struct {
	mux *http.ServeMux
}

// NewServer builds the platform REST edge (auth + OpenAPI). Product backends
// mount additional routes in your deployment binary or via reverse-proxy config.
func NewServer(auth *AuthHandlers, rl *RateLimitConfig) *Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	wrap := func(class string, h http.HandlerFunc) http.HandlerFunc {
		if rl == nil {
			return h
		}
		return rl.wrap(class, h)
	}
	admin := NewAdminHandlers(rl)
	onboard := NewOnboardHandlers(rl)

	// Global Identity & Auth
	if auth != nil {
		mux.HandleFunc("POST /api/v1/auth/otp/request", wrap("auth_otp_request", auth.RequestOTP))
		mux.HandleFunc("POST /api/v1/auth/otp/verify", wrap("auth_otp_verify", auth.VerifyOTP))
		mux.HandleFunc("POST /api/v1/auth/login", wrap("auth_password", auth.Login))
		mux.HandleFunc("POST /api/v1/auth/token/refresh", wrap("auth_refresh", auth.RefreshToken))
	}

	// Canonical System & Infrastructure Plane (Platform Ownership)
	mux.HandleFunc("POST /api/v1/system/ownership/challenge", wrap("system_ownership_challenge", admin.Challenge))
	mux.HandleFunc("POST /api/v1/system/ownership/verify", wrap("system_ownership_verify", admin.Verify))

	// Canonical Developer Experience Plane (Workstation Provisioning)
	mux.HandleFunc("POST /api/v1/dev/onboard/claim", wrap("dev_onboard_claim", onboard.Claim))

	// Backward-Compatible Aliases
	mux.HandleFunc("POST /api/v1/admin/challenge", wrap("admin_challenge", admin.Challenge))
	mux.HandleFunc("POST /api/v1/admin/verify", wrap("admin_verify", admin.Verify))
	mux.HandleFunc("POST /api/v1/onboard/claim", wrap("onboard_claim", onboard.Claim))
	mux.HandleFunc("POST /v1/onboard/claim", wrap("onboard_claim", onboard.Claim))

	// Canonical Installer
	handleInstall := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(canonicalInstallScript)
	}
	mux.HandleFunc("GET /", handleInstall)

	registerOpenAPIRoutes(mux)
	return &Server{mux: mux}
}

func (s *Server) Handler() http.Handler {
	return observability.HTTPMiddleware(s.mux)
}

func writeGRPCError(w http.ResponseWriter, err error) {
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.InvalidArgument:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": st.Message()})
			return
		case codes.Unauthenticated:
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": st.Message()})
			return
		case codes.PermissionDenied:
			writeJSON(w, http.StatusForbidden, map[string]string{"error": st.Message()})
			return
		case codes.FailedPrecondition:
			writeJSON(w, http.StatusPreconditionFailed, map[string]string{"error": st.Message()})
			return
		case codes.ResourceExhausted:
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": st.Message()})
			return
		}
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "upstream error"})
}
