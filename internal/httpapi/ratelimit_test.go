package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ratelimiting "github.com/manovaspace/orbit-rate-limiting"
)

func TestRateLimitBlocksBurst(t *testing.T) {
	rl := NewRateLimitConfig(ratelimiting.NewMemoryLimiter())
	h := rl.wrap("auth_password", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// Default limit is 10/min — fire 11
	var last int
	for i := 0; i < 11; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
		req.RemoteAddr = "203.0.113.10:1234"
		h.ServeHTTP(rec, req)
		last = rec.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("last code=%d want 429", last)
	}
}
