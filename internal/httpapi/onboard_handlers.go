package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

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

type OnboardHandlers struct {
	mu    sync.RWMutex
	cache map[string]OnboardClaimResponse
	rl    *RateLimitConfig
}

func NewOnboardHandlers(rl *RateLimitConfig) *OnboardHandlers {
	return &OnboardHandlers{
		cache: make(map[string]OnboardClaimResponse),
		rl:    rl,
	}
}

func (h *OnboardHandlers) Claim(w http.ResponseWriter, r *http.Request) {
	var body OnboardClaimRequest
	if !decodeJSONBody(w, r, &body) {
		return
	}

	token := strings.TrimSpace(body.InviteToken)
	uid := strings.ToLower(strings.TrimSpace(body.DesiredUID))
	if token == "" || uid == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invite_token and desired_uid are required"})
		return
	}

	idempKey := r.Header.Get("Idempotency-Key")
	if idempKey == "" {
		idempKey = token + ":" + uid
	}

	h.mu.RLock()
	if cached, ok := h.cache[idempKey]; ok {
		h.mu.RUnlock()
		cached.IdempotentReplay = true
		writeJSON(w, http.StatusOK, cached)
		return
	}
	h.mu.RUnlock()

	email := strings.TrimSpace(body.Email)
	if email == "" {
		email = uid + "@manova.space"
	}
	displayName := strings.TrimSpace(body.DisplayName)
	if displayName == "" {
		displayName = strings.Title(uid)
	}

	tokenHash := sha256.Sum256([]byte(token + ":" + uid))
	mcpToken := "mcp_" + hex.EncodeToString(tokenHash[:16])

	wgConf := fmt.Sprintf(`[Interface]
PrivateKey = <generated-client-key>
Address = 10.42.0.%d/32
DNS = 10.42.0.1

[Peer]
PublicKey = 4gZ+examplePublicKeyOrbitGatewayVPNControllerKey=
Endpoint = vpn.dev.manova.space:51820
AllowedIPs = 10.42.0.0/16, 172.28.0.0/16
PersistentKeepalive = 25`, (int(tokenHash[0])%200)+10)

	resp := OnboardClaimResponse{
		Status:           "provisioned",
		IdempotentReplay: false,
		User: OnboardUser{
			UID:         uid,
			Email:       email,
			DisplayName: displayName,
			Groups:      []string{"dev", "orbit"},
		},
		Credentials: OnboardCredentials{
			ForgejoUsername: uid,
			ForgejoMCPToken: mcpToken,
			WireGuardConfig: wgConf,
		},
		Workspace: OnboardWorkspaceInfo{
			GitRemoteBase:        "ssh://git@git.dev.manova.space:2222/manova",
			DefaultManifestScope: "core",
		},
	}

	h.mu.Lock()
	h.cache[idempKey] = resp
	h.mu.Unlock()

	writeJSON(w, http.StatusOK, resp)
}
