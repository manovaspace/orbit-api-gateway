package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
	"github.com/manovaspace/orbit-api-gateway/internal/domain"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/ids"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/memory"
)

func signTestJWT(t *testing.T, claims jwt.MapClaims, secret string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// TestStaffTokenAcceptedWithBreakGlassReason verifies:
// - Staff token with break-glass reason is accepted and context has staff actor.
func TestStaffTokenAcceptedWithBreakGlassReason(t *testing.T) {
	secret := "test-gateway-secret"
	svc := application.NewService(application.Deps{})
	tokens := NewTokenAuth(svc, secret)

	staffToken := signTestJWT(t, jwt.MapClaims{
		"sub":           "staff-uid-42",
		"staff_subject": "staff-uid-42",
		"is_staff":      true,
		"break_glass":   true,
		"reason":        "urgent incident response INC-999",
		"org":           "org-alpha-1",
		"exp":           time.Now().Add(time.Hour).Unix(),
	}, secret)

	var (
		gotStaffSubject string
		gotIsStaff      bool
		gotBreakGlass   bool
		gotReason       string
		gotTargetOrg    string
		gotUserID       string
		called          bool
	)

	handler := tokens.JWT(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		ctx := r.Context()
		gotStaffSubject = StaffSubjectFromContext(ctx)
		gotIsStaff = IsStaffFromContext(ctx)
		gotBreakGlass = BreakGlassFromContext(ctx)
		gotReason = BreakGlassReasonFromContext(ctx)
		gotTargetOrg = TargetOrgFromContext(ctx)
		gotUserID = UserIDFromContext(ctx)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/org-alpha-1/members", nil)
	req.Header.Set("Authorization", "Bearer "+staffToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !called {
		t.Fatal("handler was not called")
	}
	if !gotIsStaff {
		t.Error("expected IsStaff = true")
	}
	if gotStaffSubject != "staff-uid-42" {
		t.Errorf("StaffSubject = %q, want %q", gotStaffSubject, "staff-uid-42")
	}
	if !gotBreakGlass {
		t.Error("expected BreakGlass = true")
	}
	if gotReason != "urgent incident response INC-999" {
		t.Errorf("BreakGlassReason = %q, want %q", gotReason, "urgent incident response INC-999")
	}
	if gotTargetOrg != "org-alpha-1" {
		t.Errorf("TargetOrg = %q, want %q", gotTargetOrg, "org-alpha-1")
	}
	if gotUserID != "staff-uid-42" {
		t.Errorf("UserID = %q, want %q", gotUserID, "staff-uid-42")
	}
}

// TestTenantAdminAccessingStaffEndpointRejectedWithForbidden verifies:
// - Tenant admin token accessing staff endpoint is rejected with 403 Forbidden.
func TestTenantAdminAccessingStaffEndpointRejectedWithForbidden(t *testing.T) {
	secret := "test-gateway-secret"
	authFake := fakeIdentity{
		identities: map[string]domain.APIIdentity{
			"oat_tenant_admin": {UserID: "admin-user", Scopes: []string{"write"}},
		},
	}
	svc := application.NewService(application.Deps{Auth: authFake})
	tokens := NewTokenAuth(svc, secret)
	staffAuth := NewStaffAuth(tokens)

	staffOnlyHandler := staffAuth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"staff_ok"}`))
	}))

	tenantAdminToken := signTestJWT(t, jwt.MapClaims{
		"sub":      "tenant-admin-123",
		"org":      "org-corp",
		"is_staff": false,
		"exp":      time.Now().Add(time.Hour).Unix(),
	}, secret)

	staffToken := signTestJWT(t, jwt.MapClaims{
		"sub":           "staff-bob",
		"staff_subject": "staff-bob",
		"is_staff":      true,
		"break_glass":   true,
		"reason":        "support inspection",
		"org":           "org-corp",
		"exp":           time.Now().Add(time.Hour).Unix(),
	}, secret)

	tests := []struct {
		name       string
		authHeader string
		chainDual  bool
		wantStatus int
	}{
		{
			name:       "tenant admin JWT is forbidden",
			authHeader: "Bearer " + tenantAdminToken,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "tenant admin token through dual middleware is forbidden",
			authHeader: "Bearer " + tenantAdminToken,
			chainDual:  true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "tenant API token through dual middleware is forbidden",
			authHeader: "Bearer oat_tenant_admin",
			chainDual:  true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "unauthenticated request is unauthorized",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid token is unauthorized",
			authHeader: "Bearer invalid.token.value",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "staff token is accepted",
			authHeader: "Bearer " + staffToken,
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var h http.Handler
			if tc.chainDual {
				h = tokens.Dual(staffOnlyHandler)
			} else {
				h = staffOnlyHandler
			}

			req := httptest.NewRequest(http.MethodGet, "/api/v1/staff/inspect/org-corp", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

// TestStaffActionRecordsStaffIdentityInAuditEntry verifies:
// - Staff action records staff identity in audit entry.
// - Every staff read and write lands in the same audit log as a tenant admin action.
func TestStaffActionRecordsStaffIdentityInAuditEntry(t *testing.T) {
	secret := "test-audit-secret"
	auditStore := memory.NewAuditStore()
	svc := application.NewService(application.Deps{
		Audit: auditStore,
		Codes: ids.New(),
	})
	tokens := NewTokenAuth(svc, secret)

	staffToken := signTestJWT(t, jwt.MapClaims{
		"sub":           "staff-carol",
		"staff_subject": "staff-carol",
		"is_staff":      true,
		"break_glass":   true,
		"reason":        "INC-555 urgent tenant support",
		"org":           "org-acme",
		"exp":           time.Now().Add(time.Hour).Unix(),
	}, secret)

	tenantToken := signTestJWT(t, jwt.MapClaims{
		"sub":      "tenant-admin-alice",
		"org":      "org-acme",
		"is_staff": false,
		"exp":      time.Now().Add(time.Hour).Unix(),
	}, secret)

	// Protected endpoint with Dual auth and AuditHook
	auditedEndpoint := tokens.Dual(tokens.AuditHook(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})))

	// 1. Staff performs break-glass action
	staffReq := httptest.NewRequest(http.MethodPost, "/api/v1/orgs/org-acme/members", nil)
	staffReq.SetPathValue("org_id", "org-acme")
	staffReq.Header.Set("Authorization", "Bearer "+staffToken)
	staffRec := httptest.NewRecorder()
	auditedEndpoint.ServeHTTP(staffRec, staffReq)

	if staffRec.Code != http.StatusOK {
		t.Fatalf("staff request failed with code %d", staffRec.Code)
	}

	// 2. Tenant admin performs tenant action
	tenantReq := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/org-acme/members", nil)
	tenantReq.SetPathValue("org_id", "org-acme")
	tenantReq.Header.Set("Authorization", "Bearer "+tenantToken)
	tenantRec := httptest.NewRecorder()
	auditedEndpoint.ServeHTTP(tenantRec, tenantReq)

	if tenantRec.Code != http.StatusOK {
		t.Fatalf("tenant request failed with code %d", tenantRec.Code)
	}

	// 3. Inspect audit entries for org-acme: both actions must be in the same audit log
	entries, err := auditStore.ListByOrg(context.Background(), "org-acme")
	if err != nil {
		t.Fatalf("ListByOrg failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d audit entries, want 2", len(entries))
	}

	// Verify Staff Entry
	staffEntry := entries[0]
	if staffEntry.Actor != "staff-carol" {
		t.Errorf("staff entry actor = %q, want %q", staffEntry.Actor, "staff-carol")
	}
	if staffEntry.ActorType != "staff" {
		t.Errorf("staff entry actor_type = %q, want %q", staffEntry.ActorType, "staff")
	}
	if !staffEntry.IsStaff {
		t.Error("staff entry IsStaff should be true")
	}
	if !staffEntry.BreakGlass {
		t.Error("staff entry BreakGlass should be true")
	}
	if staffEntry.Reason != "INC-555 urgent tenant support" {
		t.Errorf("staff entry reason = %q, want %q", staffEntry.Reason, "INC-555 urgent tenant support")
	}
	if staffEntry.OrgID != "org-acme" {
		t.Errorf("staff entry org = %q, want %q", staffEntry.OrgID, "org-acme")
	}

	// Verify Tenant Admin Entry
	tenantEntry := entries[1]
	if tenantEntry.Actor != "tenant-admin-alice" {
		t.Errorf("tenant entry actor = %q, want %q", tenantEntry.Actor, "tenant-admin-alice")
	}
	if tenantEntry.ActorType != "user" {
		t.Errorf("tenant entry actor_type = %q, want %q", tenantEntry.ActorType, "user")
	}
	if tenantEntry.IsStaff {
		t.Error("tenant entry IsStaff should be false")
	}
	if tenantEntry.BreakGlass {
		t.Error("tenant entry BreakGlass should be false")
	}
	if tenantEntry.OrgID != "org-acme" {
		t.Errorf("tenant entry org = %q, want %q", tenantEntry.OrgID, "org-acme")
	}
}

// TestHandleStaffBreakGlassExplicit verifies the break-glass endpoint handler.
func TestHandleStaffBreakGlassExplicit(t *testing.T) {
	secret := "test-break-glass-secret"
	auditStore := memory.NewAuditStore()
	svc := application.NewService(application.Deps{
		Audit: auditStore,
		Codes: ids.New(),
	})
	tokens := NewTokenAuth(svc, secret)

	handler := tokens.JWT(http.HandlerFunc(tokens.HandleStaffBreakGlass))

	// Tenant admin calling break-glass endpoint: rejected with 403 Forbidden
	tenantToken := signTestJWT(t, jwt.MapClaims{
		"sub":      "tenant-admin-999",
		"org":      "org-beta",
		"is_staff": false,
		"exp":      time.Now().Add(time.Hour).Unix(),
	}, secret)

	reqForbidden := httptest.NewRequest(http.MethodPost, "/api/v1/staff/break-glass", nil)
	reqForbidden.Header.Set("Authorization", "Bearer "+tenantToken)
	recForbidden := httptest.NewRecorder()
	handler.ServeHTTP(recForbidden, reqForbidden)

	if recForbidden.Code != http.StatusForbidden {
		t.Fatalf("tenant admin break-glass status = %d, want 403", recForbidden.Code)
	}

	// Staff caller with reason: granted and audited
	staffToken := signTestJWT(t, jwt.MapClaims{
		"sub":           "staff-operator",
		"staff_subject": "staff-operator",
		"is_staff":      true,
		"break_glass":   true,
		"reason":        "Database restoration DR-101",
		"org":           "org-beta",
		"exp":           time.Now().Add(time.Hour).Unix(),
	}, secret)

	reqAllowed := httptest.NewRequest(http.MethodPost, "/api/v1/staff/break-glass", nil)
	reqAllowed.Header.Set("Authorization", "Bearer "+staffToken)
	recAllowed := httptest.NewRecorder()
	handler.ServeHTTP(recAllowed, reqAllowed)

	if recAllowed.Code != http.StatusOK {
		t.Fatalf("staff break-glass status = %d, want 200; body: %s", recAllowed.Code, recAllowed.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(recAllowed.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["status"] != "break_glass_granted" {
		t.Errorf("status = %v, want break_glass_granted", resp["status"])
	}
	if resp["staff_subject"] != "staff-operator" {
		t.Errorf("staff_subject = %v, want staff-operator", resp["staff_subject"])
	}

	// Verify audit log
	entries, err := auditStore.ListByOrg(context.Background(), "org-beta")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want 1", len(entries))
	}
	if entries[0].Actor != "staff-operator" || entries[0].Reason != "Database restoration DR-101" {
		t.Errorf("unexpected entry: %+v", entries[0])
	}
}

// TestDistinctStaffSecret verifies validating credentials signed with a distinct staff secret.
func TestDistinctStaffSecret(t *testing.T) {
	tenantSecret := "tenant-jwt-secret"
	staffSecret := "distinct-staff-hmac-secret"

	svc := application.NewService(application.Deps{})
	tokens := NewTokenAuth(svc, tenantSecret).WithStaffSecret(staffSecret)

	staffToken := signTestJWT(t, jwt.MapClaims{
		"sub":           "staff-dan",
		"staff_subject": "staff-dan",
		"is_staff":      true,
		"break_glass":   true,
		"reason":        "investigation",
		"org":           "org-gamma",
		"exp":           time.Now().Add(time.Hour).Unix(),
	}, staffSecret)

	var gotStaff string
	handler := tokens.RequireStaff(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotStaff = StaffSubjectFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/staff/inspect", nil)
	req.Header.Set("Authorization", "Bearer "+staffToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotStaff != "staff-dan" {
		t.Errorf("gotStaff = %q, want staff-dan", gotStaff)
	}
}
