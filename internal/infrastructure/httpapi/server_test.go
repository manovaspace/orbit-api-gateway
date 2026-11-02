package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/assets"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/clock"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/ids"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/memory"
)

// TestInstallerScriptContent asserts the script's user-visible behaviour, not
// only its HTTP shape (the shape is pinned by contract_test.go).
func TestInstallerScriptContent(t *testing.T) {
	env := newContractEnv(t, contractConfig{})

	got := send(t, env.main, http.MethodGet, "/", "", nil)
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", got.Status)
	}
	if !strings.HasPrefix(got.Body, "#!/usr/bin/env bash") {
		t.Fatalf("body does not start with a bash shebang: %q", got.Body[:min(len(got.Body), 50)])
	}
	if !strings.Contains(got.Body, "Do you want to proceed with the installation?") {
		t.Error("the interactive confirmation prompt is missing")
	}
	if !strings.Contains(got.Body, "(binary symlink)") {
		t.Error("the binary symlink shortcut is missing")
	}
}

func TestUnmappedRoutes(t *testing.T) {
	env := newContractEnv(t, contractConfig{})

	for _, path := range []string{
		"/install",
		"/install.sh",
		"/unknown",
		"/install.py",
		"/api/v1/nonexistent",
		"/installer",
		"/install/more",
	} {
		t.Run("GET "+path, func(t *testing.T) {
			got := send(t, env.main, http.MethodGet, path, "", nil)
			if got.Status != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", got.Status)
			}
		})
	}
}

func TestServerTimeouts(t *testing.T) {
	srv := NewHealth()
	config := srv.app.Config()
	if config.ReadTimeout.Seconds() != 30 || config.WriteTimeout.Seconds() != 30 || config.IdleTimeout.Seconds() != 60 {
		t.Fatalf("timeouts = read %s write %s idle %s, want 30s/30s/60s",
			config.ReadTimeout, config.WriteTimeout, config.IdleTimeout)
	}
	if config.BodyLimit != 4<<20 {
		t.Fatalf("body limit = %d, want 4 MiB", config.BodyLimit)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestAuthRoutesRequireTheUpstreamPort covers the wiring guard the old
// NewServer(auth, rl) had: without the auth port the auth routes are absent and
// every other surface still answers.
func TestAuthRoutesRequireTheUpstreamPort(t *testing.T) {
	svc := application.NewService(application.Deps{
		Clock:      clock.New(),
		Codes:      ids.New(),
		Challenges: memory.NewChallenges(),
		Claims:     memory.NewClaims(),
		Assets:     assets.New("openapi"),
	})
	base := serveOnLoopback(t, New(svc, Options{}))

	// Without the auth route the request falls through to the installer
	// catch-all, which answers POST with the mux's 405, exactly as before.
	missing := send(t, base, http.MethodPost, "/api/v1/auth/login", `{}`, nil)
	if missing.Status != http.StatusMethodNotAllowed || missing.Allow != "GET, HEAD" {
		t.Fatalf("auth route without the port = %d allow=%q", missing.Status, missing.Allow)
	}
	present := send(t, base, http.MethodPost, "/api/v1/dev/onboard/claim",
		`{"invite_token":"tok","desired_uid":"john"}`, nil)
	if present.Status != http.StatusOK {
		t.Fatalf("claim status = %d", present.Status)
	}
	if present.RateLimit != "" {
		t.Fatalf("a service without a limiter wrote rate-limit headers: %q", present.RateLimit)
	}
}
