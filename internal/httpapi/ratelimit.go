package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	ratelimiting "github.com/manovaspace/orbit-rate-limiting"
)

// RateLimitConfig holds gateway auth rate-limit settings.
type RateLimitConfig struct {
	limiter    ratelimiting.Limiter
	trustProxy bool
	policies   map[string]ratelimiting.Policy
}

// NewRateLimitConfig builds gateway rate-limit config. lim nil disables limiting.
func NewRateLimitConfig(lim ratelimiting.Limiter) *RateLimitConfig {
	if lim == nil {
		return nil
	}
	return &RateLimitConfig{
		limiter:    lim,
		trustProxy: strings.EqualFold(os.Getenv("RATE_LIMIT_TRUST_PROXY"), "true"),
		policies:   ratelimiting.DefaultAuthPolicies(),
	}
}

// NewHTTPServer returns an http.Server with conservative timeouts.
func NewHTTPServer(addr string, h http.Handler) *http.Server {
	return httpServerTimeouts(addr, h)
}

func (c *RateLimitConfig) wrap(class string, next http.HandlerFunc) http.HandlerFunc {
	if c == nil || c.limiter == nil {
		return next
	}
	policy := c.policies[class]
	return func(w http.ResponseWriter, r *http.Request) {
		if !c.allowKey(w, r, "rl:"+class+":"+clientIP(r, c.trustProxy), policy) {
			return
		}
		next(w, r)
	}
}

func (c *RateLimitConfig) allowIdentifier(w http.ResponseWriter, r *http.Request, identifier string) bool {
	if c == nil || c.limiter == nil || strings.TrimSpace(identifier) == "" {
		return true
	}
	key := "rl:auth_otp_request:id:" + hashID(identifier)
	return c.allowKey(w, r, key, ratelimiting.OTPRequestIdentifierPolicy())
}

func (c *RateLimitConfig) allowKey(w http.ResponseWriter, r *http.Request, key string, policy ratelimiting.Policy) bool {
	d, err := c.limiter.Allow(r.Context(), key, policy)
	if err != nil {
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "rate limiter unavailable"})
		return false
	}
	setRateLimitHeaders(w, d)
	if !d.Allowed {
		secs := int(d.RetryAfter.Seconds())
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return false
	}
	return true
}

func setRateLimitHeaders(w http.ResponseWriter, d ratelimiting.Decision) {
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(d.Limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(d.Remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(d.ResetAt.Unix(), 10))
}

func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func hashID(id string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(id))))
	return hex.EncodeToString(sum[:])[:16]
}

func httpServerTimeouts(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

const maxAuthBody = 64 << 10

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBody)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return false
	}
	return true
}
