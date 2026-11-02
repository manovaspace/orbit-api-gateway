package httpapi

import (
	"net/http"
	"testing"
	"time"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// TestOwnershipVerifySuccessThroughTheServer covers the one route body the
// pre-migration contract could not observe: the code only ever lived in the
// handler's memory, so the old server's success body was asserted at handler
// level. The harness now injects the code and the clock, so the whole exchange
// runs through the real server and its JSON mapping.
func TestOwnershipVerifySuccessThroughTheServer(t *testing.T) {
	env := newContractEnv(t, contractConfig{})

	challenge := send(t, env.main, http.MethodPost, "/api/v1/system/ownership/challenge",
		`{"email":"Owner@Example.com"}`, nil)
	if challenge.Status != http.StatusOK {
		t.Fatalf("challenge status = %d", challenge.Status)
	}

	got := send(t, env.main, http.MethodPost, "/api/v1/system/ownership/verify",
		`{"email":"owner@example.com","code":"123456"}`, nil)
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", got.Status)
	}
	at := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	want := `{"status":"verified","email":"owner@example.com","key_fingerprint":"` +
		domain.KeyFingerprint("owner@example.com", "123456", at) +
		`","verified_at":"2026-11-02T10:00:00Z"}` + "\n"
	if got.Body != want {
		t.Fatalf("body = %q\nwant   %q", got.Body, want)
	}

	replay := send(t, env.main, http.MethodPost, "/api/v1/system/ownership/verify",
		`{"email":"owner@example.com","code":"123456"}`, nil)
	if replay.Status != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", replay.Status)
	}
}

func TestOwnershipWrongCodeKeepsTheChallenge(t *testing.T) {
	env := newContractEnv(t, contractConfig{})

	send(t, env.main, http.MethodPost, "/api/v1/system/ownership/challenge", `{"email":"owner@example.com"}`, nil)
	wrong := send(t, env.main, http.MethodPost, "/api/v1/system/ownership/verify",
		`{"email":"owner@example.com","code":"000000"}`, nil)
	if wrong.Status != http.StatusUnauthorized {
		t.Fatalf("wrong code status = %d, want 401", wrong.Status)
	}
	right := send(t, env.main, http.MethodPost, "/api/v1/system/ownership/verify",
		`{"email":"owner@example.com","code":"123456"}`, nil)
	if right.Status != http.StatusOK {
		t.Fatalf("retry status = %d, want 200", right.Status)
	}
}
