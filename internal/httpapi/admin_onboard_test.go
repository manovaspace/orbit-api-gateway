package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminHandlers_ChallengeAndVerify(t *testing.T) {
	admin := NewAdminHandlers(nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/admin/challenge":
			admin.Challenge(w, r)
		case "/api/v1/admin/verify":
			admin.Verify(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// 1. Challenge initiation
	reqBody := AdminChallengeRequest{
		Email:       "alirezaopmc@gmail.com",
		DisplayName: "Alireza",
	}
	data, _ := json.Marshal(reqBody)
	resp, err := http.Post(server.URL+"/api/v1/admin/challenge", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("challenge POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var chalResp AdminChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&chalResp); err != nil {
		t.Fatalf("failed to decode challenge response: %v", err)
	}
	if chalResp.Status != "challenge_dispatched" {
		t.Errorf("expected status 'challenge_dispatched', got %q", chalResp.Status)
	}

	// Extract generated code directly from handler for testing
	admin.mu.RLock()
	item, ok := admin.challenges["alirezaopmc@gmail.com"]
	admin.mu.RUnlock()
	if !ok || item.code == "" {
		t.Fatalf("expected active challenge for alirezaopmc@gmail.com")
	}

	// 2. Verify with invalid code -> 401
	badVerify := AdminVerifyRequest{
		Email: "alirezaopmc@gmail.com",
		Code:  "999999",
	}
	badData, _ := json.Marshal(badVerify)
	badResp, err := http.Post(server.URL+"/api/v1/admin/verify", "application/json", bytes.NewReader(badData))
	if err != nil {
		t.Fatalf("bad verify POST failed: %v", err)
	}
	defer badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401 for bad code, got %d", badResp.StatusCode)
	}

	// 3. Verify with correct code -> 200
	goodVerify := AdminVerifyRequest{
		Email: "alirezaopmc@gmail.com",
		Code:  item.code,
	}
	goodData, _ := json.Marshal(goodVerify)
	goodResp, err := http.Post(server.URL+"/api/v1/admin/verify", "application/json", bytes.NewReader(goodData))
	if err != nil {
		t.Fatalf("good verify POST failed: %v", err)
	}
	defer goodResp.Body.Close()
	if goodResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", goodResp.StatusCode)
	}

	var verResp AdminVerifyResponse
	if err := json.NewDecoder(goodResp.Body).Decode(&verResp); err != nil {
		t.Fatalf("failed to decode verify response: %v", err)
	}
	if verResp.Status != "verified" || verResp.KeyFingerprint == "" {
		t.Errorf("unexpected verify response: %+v", verResp)
	}
}

func TestOnboardHandlers_Claim(t *testing.T) {
	onboard := NewOnboardHandlers(nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		onboard.Claim(w, r)
	}))
	defer server.Close()

	reqBody := OnboardClaimRequest{
		InviteToken:        "test-valid-invite-token",
		DesiredUID:         "john",
		Email:              "john@example.com",
		DisplayName:        "John Doe",
		SSHPublicKey:       "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... john@workstation",
		MachineFingerprint: "fingerprint-12345",
	}
	data, _ := json.Marshal(reqBody)

	// 1. Initial Claim
	req, _ := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "idemp-claim-1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("claim request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var claimResp OnboardClaimResponse
	if err := json.NewDecoder(resp.Body).Decode(&claimResp); err != nil {
		t.Fatalf("failed to decode claim response: %v", err)
	}
	if claimResp.Status != "provisioned" {
		t.Errorf("expected status 'provisioned', got %q", claimResp.Status)
	}
	if claimResp.User.UID != "john" {
		t.Errorf("expected UID 'john', got %q", claimResp.User.UID)
	}
	if claimResp.Credentials.WireGuardConfig == "" {
		t.Errorf("expected WireGuardConfig in credentials")
	}

	// 2. Idempotent Replay
	req2, _ := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(data))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Idempotency-Key", "idemp-claim-1")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("second claim request failed: %v", err)
	}
	defer resp2.Body.Close()

	var claimResp2 OnboardClaimResponse
	_ = json.NewDecoder(resp2.Body).Decode(&claimResp2)
	if !claimResp2.IdempotentReplay {
		t.Errorf("expected IdempotentReplay = true on repeated claim")
	}
}
