package httpapi

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// platformOpenAPIRoutes must stay aligned with NewServer auth registrations
// (excluding /healthz and /api/v1/openapi/*).
var platformOpenAPIRoutes = []struct {
	method string
	path   string
	opID   string
}{
	{"post", "/api/v1/auth/login", "authLogin"},
	{"post", "/api/v1/auth/otp/request", "authOtpRequest"},
	{"post", "/api/v1/auth/otp/verify", "authOtpVerify"},
	{"post", "/api/v1/auth/token/refresh", "authTokenRefresh"},
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
	b, err := os.ReadFile("../../openapi/openapi.yaml")
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}

	var doc openAPIDoc
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}

	for _, want := range platformOpenAPIRoutes {
		ops, ok := doc.Paths[want.path]
		if !ok {
			t.Errorf("openapi.yaml missing path %q", want.path)
			continue
		}
		op, ok := ops[want.method]
		if !ok {
			t.Errorf("openapi.yaml missing %s %s", want.method, want.path)
			continue
		}
		if op.OperationID != want.opID {
			t.Errorf("%s %s: operationId=%q want %q", want.method, want.path, op.OperationID, want.opID)
		}
	}

	for path, methods := range doc.Paths {
		for method := range methods {
			if !isDocumentedPlatformRoute(method, path) {
				t.Errorf("openapi.yaml has undocumented platform route %s %s (add to NewServer + platformOpenAPIRoutes)", method, path)
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
	for _, r := range platformOpenAPIRoutes {
		if r.method == method && r.path == path {
			return true
		}
	}
	return false
}
