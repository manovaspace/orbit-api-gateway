package auth

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// TestInviteMemberForwardsPhoneAndRoleAndReturnsTheTokenOnlyForPhone proves the
// adapter forwards the phone number and the tier, and hands back the raw token
// only when orbit-auth returned one.
func TestInviteMemberForwardsPhoneAndRoleAndReturnsTheTokenOnlyForPhone(t *testing.T) {
	client, stub := dialOrgStub(t, nil)
	ctx := context.Background()

	phone, err := client.InviteMember(ctx, domain.InviteRequest{OrgID: "org-1", Phone: "+989121234567", Role: "admin", AcceptURL: "https://acme.falak.demo.manova.space/invite"}, "token-1")
	if err != nil {
		t.Fatalf("phone InviteMember err = %v", err)
	}
	if phone.Token != "raw-phone-token" || phone.Invite.Phone != "+989121234567" || phone.Invite.Role != "admin" {
		t.Fatalf("phone InviteMember = %+v", phone)
	}
	if got := stub.inviteReq; got.GetPhone() != "+989121234567" || got.GetRole() != "admin" || got.GetEmail() != "" || got.GetAcceptUrl() != "https://acme.falak.demo.manova.space/invite" {
		t.Fatalf("forwarded request = %+v", got)
	}

	email, err := client.InviteMember(ctx, domain.InviteRequest{OrgID: "org-1", Email: "person@example.com", Role: "member"}, "token-1")
	if err != nil {
		t.Fatalf("email InviteMember err = %v", err)
	}
	if email.Token != "" || email.Invite.Email != "person@example.com" {
		t.Fatalf("email InviteMember = %+v, want no token", email)
	}
}

func TestGetInvitePreviewReturnsTheOrganizationAndNoRecipient(t *testing.T) {
	client, stub := dialOrgStub(t, nil)

	preview, err := client.GetInvitePreview(context.Background(), "secret-token")
	if err != nil {
		t.Fatalf("GetInvitePreview err = %v", err)
	}
	want := domain.InvitePreview{OrgID: "org-1", OrgName: "Acme", OrgSlug: "acme", Role: "admin", ExpiresAt: "2026-11-09T10:00:00Z", Channel: "email", AccountExists: true}
	if preview != want {
		t.Fatalf("GetInvitePreview = %+v, want %+v", preview, want)
	}
	if stub.previewToken != "secret-token" {
		t.Fatalf("forwarded token = %q", stub.previewToken)
	}
}

func TestAcceptInviteWithSignupForwardsTheFieldsAndReturnsTheAccount(t *testing.T) {
	client, stub := dialOrgStub(t, nil)

	accepted, err := client.AcceptInviteWithSignup(context.Background(), domain.InviteSignup{Token: "secret-token", Password: "correct horse", DisplayName: "Sara", PhoneCode: "123456"})
	if err != nil {
		t.Fatalf("AcceptInviteWithSignup err = %v", err)
	}
	if accepted != (domain.InviteAcceptance{UserID: "user-9", OrgID: "org-1", InviteID: "invite-9", Role: "member", Identifier: "+989121234567"}) {
		t.Fatalf("AcceptInviteWithSignup = %+v", accepted)
	}
	if got := stub.signupReq; got.GetToken() != "secret-token" || got.GetPassword() != "correct horse" || got.GetDisplayName() != "Sara" || got.GetPhoneCode() != "123456" {
		t.Fatalf("forwarded request = %+v", got)
	}
}

// TestAcceptInviteWithSignupMapsEachUpstreamAnswer pins the failure the edge
// renders for each upstream answer. An existing account is one stable code, and
// no failure without a client-safe meaning leaks its detail.
func TestAcceptInviteWithSignupMapsEachUpstreamAnswer(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		kind    domain.Kind
		message string
	}{
		{"not found", status.Error(codes.NotFound, "invite not found"), domain.KindNotFound, "invite not found"},
		{"already exists", status.Error(codes.AlreadyExists, "account exists: sign in to accept the invitation"), domain.KindConflict, "account_exists"},
		{"failed precondition", status.Error(codes.FailedPrecondition, "invite sign-up is disabled"), domain.KindPermissionDenied, "invite sign-up is disabled"},
		{"invalid argument", status.Error(codes.InvalidArgument, "password must be at least 8 characters"), domain.KindInvalidArgument, "password must be at least 8 characters"},
		{"phone code missing", status.Error(codes.InvalidArgument, "phone code is required"), domain.KindInvalidArgument, "phone_code is required"},
		{"wrong or expired code", status.Error(codes.Unauthenticated, "invalid otp code"), domain.KindInvalidArgument, "the code is wrong or expired"},
		{"too many attempts", status.Error(codes.Unauthenticated, "too many otp attempts"), domain.KindInvalidArgument, "the code is wrong or expired"},
		{"internal hides the detail", status.Error(codes.Internal, "pg: reset"), domain.KindBadGateway, "upstream error"},
		{"unavailable hides the detail", status.Error(codes.Unavailable, "dial tcp 10.0.0.1"), domain.KindBadGateway, "upstream error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := dialOrgStub(t, tc.err)
			_, err := client.AcceptInviteWithSignup(context.Background(), domain.InviteSignup{Token: "t", Password: "p", DisplayName: "d"})
			failure, ok := domain.AsError(err)
			if !ok || failure.Kind != tc.kind || failure.Message != tc.message {
				t.Fatalf("err = %v, want kind %v message %q", err, tc.kind, tc.message)
			}
		})
	}
}

// TestGetInvitePreviewMapsNotFoundAndHidesOtherFailures proves an unusable token
// is the not-found error whatever the reason, and that no other failure reaches
// the edge with its detail.
func TestGetInvitePreviewMapsNotFoundAndHidesOtherFailures(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		kind    domain.Kind
		message string
	}{
		{"not found", status.Error(codes.NotFound, "invite not found"), domain.KindNotFound, "invite not found"},
		{"failed precondition is not a preview answer", status.Error(codes.FailedPrecondition, "detail"), domain.KindBadGateway, "upstream error"},
		{"internal hides the detail", status.Error(codes.Internal, "pg: reset"), domain.KindBadGateway, "upstream error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := dialOrgStub(t, tc.err)
			_, err := client.GetInvitePreview(context.Background(), "t")
			failure, ok := domain.AsError(err)
			if !ok || failure.Kind != tc.kind || failure.Message != tc.message {
				t.Fatalf("err = %v, want kind %v message %q", err, tc.kind, tc.message)
			}
		})
	}
}

func TestRequestInvitePhoneCodeForwardsTheTokenAndReturnsTheExpiry(t *testing.T) {
	client, stub := dialOrgStub(t, nil)

	expiresAt, err := client.RequestInvitePhoneCode(context.Background(), "secret-token")
	if err != nil {
		t.Fatalf("RequestInvitePhoneCode err = %v", err)
	}
	if expiresAt != "2026-11-23T10:05:00Z" {
		t.Fatalf("RequestInvitePhoneCode = %q", expiresAt)
	}
	if got := stub.phoneCodeReq; got.GetToken() != "secret-token" {
		t.Fatalf("forwarded request = %+v", got)
	}
}

// TestRequestInvitePhoneCodeMapsEachUpstreamAnswer pins the failure the edge
// renders for each upstream answer. A cooldown is rate limited, a deployment
// without SMS is unavailable, and no other failure reaches the edge with its detail.
func TestRequestInvitePhoneCodeMapsEachUpstreamAnswer(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		kind    domain.Kind
		message string
	}{
		{"cooldown", status.Error(codes.ResourceExhausted, "a code was sent recently, try again shortly"), domain.KindResourceExhausted, "wait before requesting another code"},
		{"sms off", status.Error(codes.FailedPrecondition, "mobile OTP is disabled"), domain.KindUnavailable, "phone codes are not available"},
		{"sign-up disabled is also unavailable", status.Error(codes.FailedPrecondition, "invite sign-up is disabled"), domain.KindUnavailable, "phone codes are not available"},
		{"account exists", status.Error(codes.AlreadyExists, "account exists: sign in to accept the invitation"), domain.KindConflict, "account_exists"},
		{"not found", status.Error(codes.NotFound, "invite not found"), domain.KindNotFound, "invite not found"},
		{"internal hides the detail", status.Error(codes.Internal, "pg: reset"), domain.KindBadGateway, "upstream error"},
		{"unavailable hides the detail", status.Error(codes.Unavailable, "dial tcp 10.0.0.1"), domain.KindBadGateway, "upstream error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := dialOrgStub(t, tc.err)
			_, err := client.RequestInvitePhoneCode(context.Background(), "t")
			failure, ok := domain.AsError(err)
			if !ok || failure.Kind != tc.kind || failure.Message != tc.message {
				t.Fatalf("err = %v, want kind %v message %q", err, tc.kind, tc.message)
			}
		})
	}
}
