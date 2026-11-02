package domain

import (
	"strings"
	"testing"
)

// The values below are the response body the gateway served before the
// refactor for invite_token "tok-1" and uid "john".
func TestClaimCredentialsAreStable(t *testing.T) {
	got := ClaimCredentialsFor("tok-1", "john")
	if got.ForgejoUsername != "john" {
		t.Fatalf("username = %q", got.ForgejoUsername)
	}
	if got.ForgejoMCPToken != "mcp_f3bc3d3c17133acba84bdcefa610add1" {
		t.Fatalf("mcp token = %q", got.ForgejoMCPToken)
	}
	if !strings.Contains(got.WireGuardConfig, "Address = 10.42.0.53/32") {
		t.Fatalf("wireguard config = %q", got.WireGuardConfig)
	}
	if !strings.Contains(got.WireGuardConfig, "PrivateKey = <generated-client-key>") {
		t.Fatalf("wireguard config lost the placeholder key: %q", got.WireGuardConfig)
	}

	other := ClaimCredentialsFor("tok-2", "jane")
	if other.ForgejoMCPToken == got.ForgejoMCPToken {
		t.Fatal("different claims produced the same token")
	}
}

func TestClaimCredentialsHostOctetStaysInRange(t *testing.T) {
	for i := 0; i < 500; i++ {
		token := "tok-" + strings.Repeat("x", i%7) + string(rune('a'+i%26))
		config := ClaimCredentialsFor(token, "user").WireGuardConfig
		if !strings.Contains(config, "Address = 10.42.0.") {
			t.Fatalf("config = %q", config)
		}
	}
}

func TestClaimDefaults(t *testing.T) {
	email, displayName, groups := ClaimDefaults("john", "", "")
	if email != "john@manova.space" || displayName != "John" {
		t.Fatalf("defaults = %q %q", email, displayName)
	}
	if len(groups) != 2 || groups[0] != "dev" || groups[1] != "orbit" {
		t.Fatalf("groups = %v", groups)
	}

	email, displayName, _ = ClaimDefaults("john", " john@example.com ", " John Doe ")
	if email != "john@example.com" || displayName != "John Doe" {
		t.Fatalf("supplied values = %q %q", email, displayName)
	}
}

func TestNormalizeUID(t *testing.T) {
	for input, want := range map[string]string{" John ": "john", "JANE": "jane", "bob": "bob"} {
		if got := NormalizeUID(input); got != want {
			t.Fatalf("NormalizeUID(%q) = %q, want %q", input, got, want)
		}
	}
}
