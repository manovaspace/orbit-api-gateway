package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

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

type challengeItem struct {
	code      string
	expiresAt time.Time
}

type AdminHandlers struct {
	mu         sync.RWMutex
	challenges map[string]challengeItem
	rl         *RateLimitConfig
}

func NewAdminHandlers(rl *RateLimitConfig) *AdminHandlers {
	return &AdminHandlers{
		challenges: make(map[string]challengeItem),
		rl:         rl,
	}
}

func (h *AdminHandlers) Challenge(w http.ResponseWriter, r *http.Request) {
	var body AdminChallengeRequest
	if !decodeJSONBody(w, r, &body) {
		return
	}
	email := strings.TrimSpace(strings.ToLower(body.Email))
	if email == "" || !strings.Contains(email, "@") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid email is required"})
		return
	}
	if h.rl != nil && !h.rl.allowIdentifier(w, r, email) {
		return
	}

	// Generate 6-digit numeric OTP
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	code := fmt.Sprintf("%06d", (int(b[0])<<16|int(b[1])<<8|int(b[2]))%1000000)

	h.mu.Lock()
	h.challenges[email] = challengeItem{
		code:      code,
		expiresAt: time.Now().UTC().Add(10 * time.Minute),
	}
	h.mu.Unlock()

	writeJSON(w, http.StatusOK, AdminChallengeResponse{
		Status:    "challenge_dispatched",
		ExpiresIn: "10m",
	})
}

func (h *AdminHandlers) Verify(w http.ResponseWriter, r *http.Request) {
	var body AdminVerifyRequest
	if !decodeJSONBody(w, r, &body) {
		return
	}
	email := strings.TrimSpace(strings.ToLower(body.Email))
	code := strings.TrimSpace(body.Code)
	if email == "" || code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and code are required"})
		return
	}

	h.mu.Lock()
	item, ok := h.challenges[email]
	if !ok || time.Now().UTC().After(item.expiresAt) || item.code != code {
		h.mu.Unlock()
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired verification code"})
		return
	}
	delete(h.challenges, email)
	h.mu.Unlock()

	hash := sha256.Sum256([]byte(email + ":" + code + ":" + time.Now().UTC().String()))
	fingerprint := hex.EncodeToString(hash[:16])

	writeJSON(w, http.StatusOK, AdminVerifyResponse{
		Status:         "verified",
		Email:          email,
		KeyFingerprint: fingerprint,
		VerifiedAt:     time.Now().UTC(),
	})
}
