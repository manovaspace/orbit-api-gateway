package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/ratelimit"
)

func TestSessionUsernameSetForwardsTheBearerAndReturnsTheStoredForm(t *testing.T) {
	stub := &authUpstreamStub{}
	base := newGoogleEnv(t, stub, nil)

	got := send(t, base, http.MethodPut, routeSessionUsername, `{"username":"Sara.K"}`, bearer())
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", got.Status)
	}
	if want := `{"username":"sara.k"}` + "\n"; got.Body != want {
		t.Fatalf("body = %q, want %q", got.Body, want)
	}
	req, calls, authorization := stub.usernameSeen()
	if calls != 1 || req.GetUsername() != "Sara.K" {
		t.Fatalf("forwarded username = %+v (calls %d)", req, calls)
	}
	if authorization != "Bearer "+testAccessToken {
		t.Fatalf("forwarded authorization = %q", authorization)
	}
}

func TestSessionUsernameNeedsTheBearerTokenBeforeAnyUpstreamCall(t *testing.T) {
	stub := &authUpstreamStub{}
	base := newGoogleEnv(t, stub, nil)

	got := send(t, base, http.MethodPut, routeSessionUsername, `{"username":"sara.k"}`, nil)
	if got.Status != http.StatusUnauthorized || got.Body != `{"error":"missing bearer token"}`+"\n" {
		t.Fatalf("status = %d body = %q", got.Status, got.Body)
	}
	if _, calls, _ := stub.usernameSeen(); calls != 0 {
		t.Fatalf("a request without a bearer token reached orbit-auth %d times", calls)
	}
}

func TestSessionUsernameMalformedBodyIsA400(t *testing.T) {
	stub := &authUpstreamStub{}
	base := newGoogleEnv(t, stub, nil)

	got := send(t, base, http.MethodPut, routeSessionUsername, `{"username":`, bearer())
	if got.Status != http.StatusBadRequest || got.Body != `{"error":"invalid json"}`+"\n" {
		t.Fatalf("status = %d body = %q", got.Status, got.Body)
	}
	if _, calls, _ := stub.usernameSeen(); calls != 0 {
		t.Fatalf("a malformed body reached orbit-auth %d times", calls)
	}
}

func TestSessionUsernameErrorMapping(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string
	}{
		{"taken is a conflict", status.Error(codes.AlreadyExists, "username taken"), http.StatusConflict, `{"error":"username taken"}` + "\n"},
		{"invalid username", status.Error(codes.InvalidArgument, "username too short"), http.StatusBadRequest, `{"error":"username too short"}` + "\n"},
		{"unauthenticated", status.Error(codes.Unauthenticated, "authentication required"), http.StatusUnauthorized, `{"error":"authentication required"}` + "\n"},
		{"permission denied", status.Error(codes.PermissionDenied, "not allowed"), http.StatusForbidden, `{"error":"not allowed"}` + "\n"},
		{"internal hides the detail", status.Error(codes.Internal, "pg: connection reset"), http.StatusBadGateway, `{"error":"upstream error"}` + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &authUpstreamStub{err: tc.err}
			base := newGoogleEnv(t, stub, nil)

			got := send(t, base, http.MethodPut, routeSessionUsername, `{"username":"sara.k"}`, bearer())
			if got.Status != tc.wantStatus || got.Body != tc.wantBody {
				t.Fatalf("status = %d body = %q, want %d %q", got.Status, got.Body, tc.wantStatus, tc.wantBody)
			}
		})
	}
}

func TestSessionUsernameRejectsOtherMethods(t *testing.T) {
	stub := &authUpstreamStub{}
	base := newGoogleEnv(t, stub, nil)

	got := send(t, base, http.MethodPost, routeSessionUsername, `{"username":"sara.k"}`, bearer())
	if got.Status != http.StatusMethodNotAllowed || !strings.Contains(got.Allow, http.MethodPut) {
		t.Fatalf("status = %d allow = %q, want 405 listing PUT", got.Status, got.Allow)
	}
	if _, calls, _ := stub.usernameSeen(); calls != 0 {
		t.Fatalf("a wrong-method request reached orbit-auth %d times", calls)
	}
}

func TestSessionUsernameUsesTheSignupPerIPBudget(t *testing.T) {
	limiter := &recordingLimiter{allow: true}
	stub := &authUpstreamStub{}
	base := newGoogleEnv(t, stub, limiter)

	if got := send(t, base, http.MethodPut, routeSessionUsername, `{"username":"sara.k"}`, bearer()); got.Status != http.StatusOK {
		t.Fatalf("status = %d", got.Status)
	}
	want := ratelimit.KeyForIP("127.0.0.1", routeSessionUsername)
	if len(limiter.keys) != 1 || limiter.keys[0] != want {
		t.Fatalf("limiter keys = %v, want %q", limiter.keys, want)
	}
	if limiter.policies[0] != domain.IPRoutePolicy(routeSessionUsername, domain.SignupIPLimit) {
		t.Fatalf("policy = %+v", limiter.policies[0])
	}
}
