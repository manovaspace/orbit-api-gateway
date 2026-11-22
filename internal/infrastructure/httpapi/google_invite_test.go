package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
)

func TestGoogleStartForwardsATrimmedInviteToken(t *testing.T) {
	stub := &authUpstreamStub{}
	base := newGoogleEnv(t, stub, nil)

	body := `{"redirect_uri":"https://app.example.test/callback","return_to":"/home","invite_token":"  inv-token  "}`
	got := send(t, base, http.MethodPost, routeGoogleStart, body, nil)
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, body %q", got.Status, got.Body)
	}
	start, _, _, _ := stub.googleSeen()
	if start.GetInviteToken() != "inv-token" {
		t.Fatalf("forwarded invite token = %q, want the trimmed value", start.GetInviteToken())
	}
}

func TestGoogleStartRejectsAnOversizedInviteTokenBeforeOrbitAuth(t *testing.T) {
	stub := &authUpstreamStub{}
	base := newGoogleEnv(t, stub, nil)

	token := strings.Repeat("t", 513)
	body := `{"redirect_uri":"https://app.example.test/callback","invite_token":"` + token + `"}`
	got := send(t, base, http.MethodPost, routeGoogleStart, body, nil)
	if got.Status != http.StatusBadRequest || errorCode(t, got) != "invite_invalid" {
		t.Fatalf("status %d body %q, want 400 invite_invalid", got.Status, got.Body)
	}
	if _, _, calls, _ := stub.googleSeen(); calls != 0 {
		t.Fatalf("upstream calls = %d, want 0", calls)
	}
}

// TestGoogleInviteRefusalsCarryTheirCodes checks each invitation refusal that the
// Google start and completion routes can return.
func TestGoogleInviteRefusalsCarryTheirCodes(t *testing.T) {
	cases := []struct {
		name   string
		route  string
		body   string
		err    error
		status int
		code   string
	}{
		{"phone invitation needs a password", routeGoogleStart, googleStartBodyOK,
			status.Error(codes.FailedPrecondition, "google cannot accept a phone invitation"), http.StatusPreconditionFailed, "invite_needs_password"},
		{"invitation invalid on start", routeGoogleStart, googleStartBodyOK,
			status.Error(codes.InvalidArgument, "invalid invite"), http.StatusBadRequest, "invite_invalid"},
		{"invitation invalid on complete", routeGoogleComplete, googleCompleteBodyOK,
			status.Error(codes.InvalidArgument, "invalid invite"), http.StatusBadRequest, "invite_invalid"},
		{"account not allowed", routeGoogleComplete, googleCompleteBodyOK,
			status.Error(codes.PermissionDenied, "account not allowed"), http.StatusForbidden, "google_not_allowed"},
		{"sign-up disabled for the invitation", routeGoogleComplete, googleCompleteBodyOK,
			status.Error(codes.FailedPrecondition, "invite sign-up is disabled"), http.StatusPreconditionFailed, "sign_up_disabled"},
		{"email does not match the invitation", routeGoogleComplete, googleCompleteBodyOK,
			status.Error(codes.FailedPrecondition, "invite email mismatch"), http.StatusConflict, "google_email_mismatch"},
		{"state expired or failed exchange", routeGoogleComplete, googleCompleteBodyOK,
			status.Error(codes.Unauthenticated, "google sign-in failed"), http.StatusBadRequest, "state_expired"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := &authUpstreamStub{err: c.err}
			base := newGoogleEnv(t, stub, nil)

			got := send(t, base, http.MethodPost, c.route, c.body, nil)
			if got.Status != c.status {
				t.Fatalf("status = %d, want %d (body %q)", got.Status, c.status, got.Body)
			}
			if code := errorCode(t, got); code != c.code {
				t.Fatalf("code = %q, want %q (body %q)", code, c.code, got.Body)
			}
		})
	}
}

// TestGoogleCompleteAddsTheInvitationFields checks the body of an invitation
// sign-in. A plain sign-in keeps its original body; that is pinned by
// TestGoogleCompleteReturnsTheTokenFieldsReturnToAndNoStore.
func TestGoogleCompleteAddsTheInvitationFields(t *testing.T) {
	stub := &authUpstreamStub{inviteResp: &authv1.CompleteGoogleSignInResponse{
		Tokens: &authv1.TokenResponse{
			AccessToken:  "access-google",
			RefreshToken: "refresh-google",
			ExpiresAt:    "2026-11-02T11:00:00Z",
		},
		ReturnTo:      "/home",
		InviteId:      "inv-1",
		OrgId:         "org-1",
		OrgSlug:       "acme",
		Role:          "member",
		AlreadyMember: false,
	}}
	base := newGoogleEnv(t, stub, nil)

	got := send(t, base, http.MethodPost, routeGoogleComplete, googleCompleteBodyOK, nil)
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, body %q", got.Status, got.Body)
	}
	want := `{"access_token":"access-google","already_member":false,"expires_at":"2026-11-02T11:00:00Z","invite_id":"inv-1","org_id":"org-1","org_slug":"acme","refresh_token":"refresh-google","return_to":"/home","role":"member"}` + "\n"
	if got.Body != want {
		t.Fatalf("body = %q\nwant   %q", got.Body, want)
	}
}

// TestGoogleCompleteOmitsEmptyInvitationFields checks that an invitation with no
// role or slug leaves those fields out, and that already_member is present.
func TestGoogleCompleteOmitsEmptyInvitationFields(t *testing.T) {
	stub := &authUpstreamStub{inviteResp: &authv1.CompleteGoogleSignInResponse{
		Tokens: &authv1.TokenResponse{
			AccessToken:  "access-google",
			RefreshToken: "refresh-google",
			ExpiresAt:    "2026-11-02T11:00:00Z",
		},
		ReturnTo:      "/home",
		InviteId:      "inv-2",
		OrgId:         "org-2",
		AlreadyMember: true,
	}}
	base := newGoogleEnv(t, stub, nil)

	got := send(t, base, http.MethodPost, routeGoogleComplete, googleCompleteBodyOK, nil)
	want := `{"access_token":"access-google","already_member":true,"expires_at":"2026-11-02T11:00:00Z","invite_id":"inv-2","org_id":"org-2","refresh_token":"refresh-google","return_to":"/home"}` + "\n"
	if got.Body != want {
		t.Fatalf("body = %q\nwant   %q", got.Body, want)
	}
}
