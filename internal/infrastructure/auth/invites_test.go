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

	phone, err := client.InviteMember(ctx, domain.InviteRequest{OrgID: "org-1", Phone: "+989121234567", Role: "admin"}, "token-1")
	if err != nil {
		t.Fatalf("phone InviteMember err = %v", err)
	}
	if phone.Token != "raw-phone-token" || phone.Invite.Phone != "+989121234567" || phone.Invite.Role != "admin" {
		t.Fatalf("phone InviteMember = %+v", phone)
	}
	if got := stub.inviteReq; got.GetPhone() != "+989121234567" || got.GetRole() != "admin" || got.GetEmail() != "" {
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
	want := domain.InvitePreview{OrgID: "org-1", OrgName: "Acme", OrgSlug: "acme", Role: "admin", ExpiresAt: "2026-11-09T10:00:00Z"}
	if preview != want {
		t.Fatalf("GetInvitePreview = %+v, want %+v", preview, want)
	}
	if stub.previewToken != "secret-token" {
		t.Fatalf("forwarded token = %q", stub.previewToken)
	}
}

func TestAcceptInviteWithSignupForwardsTheFieldsAndReturnsTheAccount(t *testing.T) {
	client, stub := dialOrgStub(t, nil)

	accepted, err := client.AcceptInviteWithSignup(context.Background(), domain.InviteSignup{Token: "secret-token", Password: "correct horse", DisplayName: "Sara"})
	if err != nil {
		t.Fatalf("AcceptInviteWithSignup err = %v", err)
	}
	if accepted != (domain.InviteAcceptance{UserID: "user-9", OrgID: "org-1"}) {
		t.Fatalf("AcceptInviteWithSignup = %+v", accepted)
	}
	if got := stub.signupReq; got.GetToken() != "secret-token" || got.GetPassword() != "correct horse" || got.GetDisplayName() != "Sara" {
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
