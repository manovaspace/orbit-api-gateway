package httpapi

import (
	"net/http"
	"time"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// handlers serves the edge's routes. Every route is a plain net/http handler,
// adapted to Fiber v3 by the server; the shapes below are the external contract.
type handlers struct {
	svc    *application.Service
	client clientAddr
}

func (h *handlers) health(w http.ResponseWriter, _ *http.Request) {
	// The previous net/http server answered without an explicit Content-Type and
	// net/http sniffed text/plain. Set it explicitly so the adapted response is
	// byte-identical and fasthttp never invents a header.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// install serves the canonical installer at / only. Every other path that
// reaches this catch-all is a 404, exactly as the net/http mux behaved.
func (h *handlers) install(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.svc.InstallScript())
}

// wrap applies one rate-limit class to a route. Without a limiter the route is
// untouched and writes no rate-limit header.
func (h *handlers) wrap(class string, next http.HandlerFunc) http.HandlerFunc {
	if !h.svc.HasLimiter() {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		decision, err := h.svc.CheckClassLimit(r.Context(), class, h.client.ip(r))
		if err != nil {
			writeLimitError(w, err)
			return
		}
		setRateLimitHeaders(w, decision)
		next(w, r)
	}
}

type otpRequestBody struct {
	Identifier    string `json:"identifier"`
	Channel       string `json:"channel"`
	Email         string `json:"email"`
	CorrelationID string `json:"correlation_id"`
}

type otpVerifyBody struct {
	Identifier string `json:"identifier"`
	Channel    string `json:"channel"`
	Email      string `json:"email"`
	Code       string `json:"code"`
}

type refreshBody struct {
	RefreshToken string `json:"refresh_token"`
}

type loginBody struct {
	Identifier string `json:"identifier"`
	Email      string `json:"email"`
	Password   string `json:"password"`
}

func (h *handlers) requestOTP(w http.ResponseWriter, r *http.Request) {
	var body otpRequestBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	receipt, err := h.svc.RequestOTP(r.Context(), domain.OTPRequest{
		Identifier:    body.Identifier,
		Channel:       body.Channel,
		Email:         body.Email,
		CorrelationID: body.CorrelationID,
	})
	if err != nil {
		writeLimitError(w, err)
		return
	}
	if receipt.IdentifierLimit != nil {
		setRateLimitHeaders(w, *receipt.IdentifierLimit)
	}
	writeJSON(w, http.StatusOK, map[string]string{"expires_at": receipt.ExpiresAt})
}

func (h *handlers) verifyOTP(w http.ResponseWriter, r *http.Request) {
	var body otpVerifyBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	tokens, err := h.svc.VerifyOTP(r.Context(), domain.OTPVerification{
		Identifier: body.Identifier,
		Channel:    body.Channel,
		Email:      body.Email,
		Code:       body.Code,
	})
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeTokens(w, tokens)
}

func (h *handlers) login(w http.ResponseWriter, r *http.Request) {
	var body loginBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	tokens, err := h.svc.Login(r.Context(), domain.PasswordLogin{
		Identifier: body.Identifier,
		Email:      body.Email,
		Password:   body.Password,
	})
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeTokens(w, tokens)
}

func (h *handlers) refreshToken(w http.ResponseWriter, r *http.Request) {
	var body refreshBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	tokens, err := h.svc.RefreshToken(r.Context(), body.RefreshToken)
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeTokens(w, tokens)
}

func (h *handlers) revokeToken(w http.ResponseWriter, r *http.Request) {
	var body refreshBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if err := h.svc.RevokeRefreshToken(r.Context(), body.RefreshToken); err != nil {
		writeAppError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeTokens renders the token envelope. Encoding a map keeps the keys in
// their historical alphabetical order, so the body bytes do not change.
func writeTokens(w http.ResponseWriter, tokens domain.TokenPair) {
	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"expires_at":    tokens.ExpiresAt,
	})
}

type AdminChallengeRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name,omitempty"`
}

type AdminChallengeResponse struct {
	Status    string `json:"status"`
	ExpiresIn string `json:"expires_in"`
}

type AdminVerifyRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type AdminVerifyResponse struct {
	Status         string    `json:"status"`
	Email          string    `json:"email"`
	DisplayName    string    `json:"display_name,omitempty"`
	KeyFingerprint string    `json:"key_fingerprint"`
	VerifiedAt     time.Time `json:"verified_at"`
}

func (h *handlers) challenge(w http.ResponseWriter, r *http.Request) {
	var body AdminChallengeRequest
	if !decodeJSONBody(w, r, &body) {
		return
	}
	receipt, err := h.svc.Challenge(r.Context(), body.Email)
	if err != nil {
		writeLimitError(w, err)
		return
	}
	if receipt.IdentifierLimit != nil {
		setRateLimitHeaders(w, *receipt.IdentifierLimit)
	}
	writeJSON(w, http.StatusOK, AdminChallengeResponse{
		Status:    receipt.Grant.Status,
		ExpiresIn: receipt.Grant.ExpiresIn,
	})
}

func (h *handlers) verifyChallenge(w http.ResponseWriter, r *http.Request) {
	var body AdminVerifyRequest
	if !decodeJSONBody(w, r, &body) {
		return
	}
	proof, err := h.svc.VerifyChallenge(r.Context(), body.Email, body.Code)
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, AdminVerifyResponse{
		Status:         proof.Status,
		Email:          proof.Email,
		DisplayName:    proof.DisplayName,
		KeyFingerprint: proof.KeyFingerprint,
		VerifiedAt:     proof.VerifiedAt,
	})
}

type OnboardClaimRequest struct {
	InviteToken        string            `json:"invite_token"`
	DesiredUID         string            `json:"desired_uid"`
	Email              string            `json:"email,omitempty"`
	DisplayName        string            `json:"display_name,omitempty"`
	SSHPublicKey       string            `json:"ssh_public_key"`
	MachineFingerprint string            `json:"machine_fingerprint,omitempty"`
	Scope              string            `json:"scope,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

type OnboardUser struct {
	UID         string   `json:"uid"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Groups      []string `json:"groups"`
}

type OnboardCredentials struct {
	ForgejoUsername string `json:"forgejo_username"`
	ForgejoMCPToken string `json:"forgejo_mcp_token"`
	WireGuardConfig string `json:"wireguard_config"`
}

type OnboardWorkspaceInfo struct {
	GitRemoteBase        string `json:"git_remote_base"`
	DefaultManifestScope string `json:"default_manifest_scope"`
}

type OnboardClaimResponse struct {
	Status           string               `json:"status"`
	IdempotentReplay bool                 `json:"idempotent_replay"`
	User             OnboardUser          `json:"user"`
	Credentials      OnboardCredentials   `json:"credentials"`
	Workspace        OnboardWorkspaceInfo `json:"workspace"`
}

func (h *handlers) claim(w http.ResponseWriter, r *http.Request) {
	var body OnboardClaimRequest
	if !decodeJSONBody(w, r, &body) {
		return
	}
	result, err := h.svc.Claim(r.Context(), domain.ClaimInput{
		InviteToken:        body.InviteToken,
		DesiredUID:         body.DesiredUID,
		Email:              body.Email,
		DisplayName:        body.DisplayName,
		SSHPublicKey:       body.SSHPublicKey,
		MachineFingerprint: body.MachineFingerprint,
		Scope:              body.Scope,
		Metadata:           body.Metadata,
	}, r.Header.Get("Idempotency-Key"))
	if err != nil {
		writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, OnboardClaimResponse{
		Status:           result.Status,
		IdempotentReplay: result.IdempotentReplay,
		User: OnboardUser{
			UID:         result.User.UID,
			Email:       result.User.Email,
			DisplayName: result.User.DisplayName,
			Groups:      result.User.Groups,
		},
		Credentials: OnboardCredentials{
			ForgejoUsername: result.Credentials.ForgejoUsername,
			ForgejoMCPToken: result.Credentials.ForgejoMCPToken,
			WireGuardConfig: result.Credentials.WireGuardConfig,
		},
		Workspace: OnboardWorkspaceInfo{
			GitRemoteBase:        result.Workspace.GitRemoteBase,
			DefaultManifestScope: result.Workspace.DefaultManifestScope,
		},
	})
}
