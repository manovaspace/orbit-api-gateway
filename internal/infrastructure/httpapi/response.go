package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// maxAuthBody caps every JSON request body the edge decodes.
const maxAuthBody = 64 << 10

// writeJSON writes the edge's JSON envelope. The trailing newline comes from
// the encoder and is part of the contract.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// decodeJSONBody decodes one JSON value and reports whether the request may
// continue.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBody)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return false
	}
	return true
}

// writeAppError maps a domain failure onto the status code and body the edge
// has always returned for it.
func writeAppError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	message := "upstream error"
	if failure, ok := domain.AsError(err); ok {
		message = failure.Message
		switch failure.Kind {
		case domain.KindInvalidArgument:
			status = http.StatusBadRequest
		case domain.KindUnauthenticated:
			status = http.StatusUnauthorized
		case domain.KindPermissionDenied:
			status = http.StatusForbidden
		case domain.KindFailedPrecondition:
			status = http.StatusPreconditionFailed
		case domain.KindResourceExhausted:
			status = http.StatusTooManyRequests
		case domain.KindNotFound:
			status = http.StatusNotFound
		case domain.KindConflict:
			status = http.StatusConflict
		case domain.KindBadGateway:
			status = http.StatusBadGateway
		}
	}
	writeJSON(w, status, map[string]string{"error": message})
}

// writeLimitError renders a rejected or unavailable rate-limit check. A denied
// request still carries the remaining-budget headers.
func writeLimitError(w http.ResponseWriter, err error) {
	var limit *domain.LimitError
	if !errors.As(err, &limit) {
		writeAppError(w, err)
		return
	}
	if limit.Unavailable {
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "rate limiter unavailable"})
		return
	}
	setRateLimitHeaders(w, limit.Decision)
	seconds := int(limit.Decision.RetryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
}

func setRateLimitHeaders(w http.ResponseWriter, decision domain.Decision) {
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(decision.Limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(decision.Remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(decision.ResetAt.Unix(), 10))
}
