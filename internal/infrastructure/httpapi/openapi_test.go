package httpapi

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// platformOpenAPIRoutes must stay aligned with the New registrations
// (excluding /healthz, the installer and /api/v1/openapi/*).
var platformOpenAPIRoutes = []struct {
	method string
	path   string
	opID   string
}{
	{"post", "/api/v1/auth/login", "authLogin"},
	{"post", "/api/v1/auth/otp/request", "authOtpRequest"},
	{"post", "/api/v1/auth/otp/verify", "authOtpVerify"},
	{"post", "/api/v1/auth/token/refresh", "authTokenRefresh"},
	{"post", "/api/v1/auth/signup", "authSignup"},
	{"post", "/api/v1/auth/signup/verify", "authSignupVerify"},
	{"get", "/api/v1/orgs", "orgList"},
	{"post", "/api/v1/orgs", "orgCreate"},
	{"get", "/api/v1/orgs/{org_id}/members", "orgMembersList"},
	{"post", "/api/v1/orgs/{org_id}/invites", "orgInviteCreate"},
	{"get", "/api/v1/orgs/{org_id}/invites", "orgInviteList"},
	{"delete", "/api/v1/orgs/{org_id}/invites/{invite_id}", "orgInviteRevoke"},
	{"post", "/api/v1/invites/accept", "inviteAccept"},
	{"post", "/api/v1/session/org", "sessionSelectOrg"},
	{"post", "/api/v1/system/ownership/challenge", "systemOwnershipChallenge"},
	{"post", "/api/v1/system/ownership/verify", "systemOwnershipVerify"},
	{"post", "/api/v1/dev/onboard/claim", "devOnboardClaim"},
	{"post", "/api/v1/admin/challenge", "adminChallenge"},
	{"post", "/api/v1/admin/verify", "adminVerify"},
	{"post", "/api/v1/onboard/claim", "onboardClaim"},
}

type openAPIDoc struct {
	Paths map[string]map[string]struct {
		OperationID string `yaml:"operationId"`
	} `yaml:"paths"`
	Components struct {
		Schemas map[string]any `yaml:"schemas"`
	} `yaml:"components"`
}

func TestOpenAPISpecParity(t *testing.T) {
	body, err := os.ReadFile("../../../openapi/openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}

	var doc openAPIDoc
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}

	for _, want := range platformOpenAPIRoutes {
		operations, ok := doc.Paths[want.path]
		if !ok {
			t.Errorf("openapi.yaml missing path %q", want.path)
			continue
		}
		operation, ok := operations[want.method]
		if !ok {
			t.Errorf("openapi.yaml missing %s %s", want.method, want.path)
			continue
		}
		if operation.OperationID != want.opID {
			t.Errorf("%s %s: operationId=%q want %q", want.method, want.path, operation.OperationID, want.opID)
		}
	}

	for path, methods := range doc.Paths {
		for method := range methods {
			if !isDocumentedPlatformRoute(method, path) {
				t.Errorf("openapi.yaml has undocumented platform route %s %s (add to New + platformOpenAPIRoutes)", method, path)
			}
		}
	}

	for _, schema := range []string{"TokenPair", "OtpRequestResponse", "ErrorEnvelope"} {
		if _, ok := doc.Components.Schemas[schema]; !ok {
			t.Errorf("openapi.yaml missing schema %q", schema)
		}
	}
}

func isDocumentedPlatformRoute(method, path string) bool {
	for _, route := range platformOpenAPIRoutes {
		if route.method == method && route.path == path {
			return true
		}
	}
	return false
}
