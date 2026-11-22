package auth

import (
	"context"
	"net"
	"sync"
	"testing"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// staffStub is the in-process StaffOrgService. It records the metadata and the
// requests the adapter sends.
type staffStub struct {
	authv1.UnimplementedStaffOrgServiceServer

	mu        sync.Mutex
	md        metadata.MD
	provision *authv1.ProvisionOrganizationRequest
	reinvite  *authv1.ReinviteOwnerRequest
}

func (s *staffStub) ProvisionOrganization(ctx context.Context, in *authv1.ProvisionOrganizationRequest) (*authv1.ProvisionOrganizationResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.mu.Lock()
	s.md, s.provision = md, in
	s.mu.Unlock()
	return &authv1.ProvisionOrganizationResponse{Organization: &authv1.StaffOrganization{Id: "org-1"}, OwnerInvite: &authv1.StaffInvite{Id: "invite-1"}}, nil
}

func (s *staffStub) ReinviteOwner(ctx context.Context, in *authv1.ReinviteOwnerRequest) (*authv1.ReinviteOwnerResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.mu.Lock()
	s.md, s.reinvite = md, in
	s.mu.Unlock()
	return &authv1.ReinviteOwnerResponse{Invite: &authv1.StaffInvite{Id: "invite-2"}}, nil
}

func (s *staffStub) GetOrganization(ctx context.Context, _ *authv1.GetOrganizationRequest) (*authv1.GetOrganizationResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.mu.Lock()
	s.md = md
	s.mu.Unlock()
	return &authv1.GetOrganizationResponse{Organization: &authv1.StaffOrganization{Id: "org-1"}}, nil
}

func dialStaffStub(t *testing.T, token string) (*Client, *staffStub) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stub := &staffStub{}
	gs := grpc.NewServer()
	authv1.RegisterStaffOrgServiceServer(gs, stub)
	go func() { _ = gs.Serve(listener) }()
	t.Cleanup(gs.Stop)

	client, err := NewClient(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	client.StaffServiceToken = token
	return client, stub
}

func TestStaffProvisionForwardsAcceptURLWithServiceMetadata(t *testing.T) {
	client, stub := dialStaffStub(t, "svc-token")
	actor := domain.StaffActor{Subject: "keycloak:user-1", Reason: "new client"}

	_, err := client.ProvisionOrganization(context.Background(), actor, domain.StaffProvisionRequest{
		Name: "Acme", OwnerEmail: "owner@example.com", IdempotencyKey: "key-1",
		AcceptURL: "https://{slug}.falak.demo.manova.space/invite",
	})
	if err != nil {
		t.Fatalf("ProvisionOrganization err = %v", err)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if got := stub.provision.GetAcceptUrl(); got != "https://{slug}.falak.demo.manova.space/invite" {
		t.Fatalf("forwarded accept_url = %q", got)
	}
	if got := stub.md.Get("x-orbit-service-token"); len(got) != 1 || got[0] != "svc-token" {
		t.Fatalf("service token metadata = %q", got)
	}
	if got := stub.md.Get("x-staff-subject"); len(got) != 1 || got[0] != "keycloak:user-1" {
		t.Fatalf("subject metadata = %q", got)
	}
	if got := stub.md.Get("x-staff-reason-bin"); len(got) != 1 || got[0] != "new client" {
		t.Fatalf("reason metadata = %q", got)
	}
}

func TestStaffReinviteOwnerForwardsAcceptURL(t *testing.T) {
	client, stub := dialStaffStub(t, "svc-token")

	_, err := client.ReinviteOwner(context.Background(), domain.StaffActor{Subject: "keycloak:user-1", Reason: "rotate"}, domain.StaffOwnerInviteRequest{
		OrgID: "org-1", OwnerPhone: "+989121234567", AcceptURL: "https://acme.falak.demo.manova.space/invite",
	})
	if err != nil {
		t.Fatalf("ReinviteOwner err = %v", err)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if got := stub.reinvite.GetAcceptUrl(); got != "https://acme.falak.demo.manova.space/invite" {
		t.Fatalf("forwarded accept_url = %q", got)
	}
	if got := stub.reinvite.GetOwnerPhone(); got != "+989121234567" {
		t.Fatalf("forwarded owner_phone = %q", got)
	}
}

func TestStaffReadCarriesNoReason(t *testing.T) {
	client, stub := dialStaffStub(t, "svc-token")

	if _, err := client.GetOrganization(context.Background(), domain.StaffActor{Subject: "keycloak:user-1"}, "org-1"); err != nil {
		t.Fatalf("GetOrganization err = %v", err)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if got := stub.md.Get("x-staff-reason-bin"); len(got) != 0 {
		t.Fatalf("a read carried a reason: %q", got)
	}
}
