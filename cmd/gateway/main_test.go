package main

import "testing"

func TestResolveJWTSecret(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		dev    bool
		want   string
	}{
		{"explicit secret wins", "s3cret", true, "s3cret"},
		{"explicit secret outside dev", "s3cret", false, "s3cret"},
		{"dev falls back", "", true, "dev-insecure-change-me"},
		{"production stays empty", "", false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveJWTSecret(tc.secret, tc.dev); got != tc.want {
				t.Fatalf("resolveJWTSecret(%q, %v) = %q, want %q", tc.secret, tc.dev, got, tc.want)
			}
		})
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("ORBIT_GATEWAY_TEST_VALUE", "")
	if got := envOr("ORBIT_GATEWAY_TEST_VALUE", "fallback"); got != "fallback" {
		t.Fatalf("envOr with an empty value = %q, want fallback", got)
	}
	t.Setenv("ORBIT_GATEWAY_TEST_VALUE", "set")
	if got := envOr("ORBIT_GATEWAY_TEST_VALUE", "fallback"); got != "set" {
		t.Fatalf("envOr = %q, want set", got)
	}
}
