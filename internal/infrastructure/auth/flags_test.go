package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

func newFlagTestClient(t *testing.T, serverURL string) *Client {
	t.Helper()
	client, err := NewClient("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	client.AuthHTTPURL = serverURL
	return client
}

func TestListFlagsForwardsTheDocument(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"2026-11-03T10:00:00Z","flags":[{"name":"beta","enabled":true,"description":"Beta access"}]}`))
	}))
	t.Cleanup(server.Close)

	client := newFlagTestClient(t, server.URL)
	set, err := client.ListFlags(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != flagsPath {
		t.Fatalf("path = %q, want %q", gotPath, flagsPath)
	}
	if set.Version != "2026-11-03T10:00:00Z" {
		t.Fatalf("version = %q", set.Version)
	}
	if len(set.Flags) != 1 {
		t.Fatalf("flags = %+v", set.Flags)
	}
	got := set.Flags[0]
	if got.Name != "beta" || !got.Enabled || got.Description != "Beta access" {
		t.Fatalf("flag = %+v", got)
	}
}

func TestListFlagsTreatsNon200AsAnUpstreamFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"secret":"must not leak"}`))
	}))
	t.Cleanup(server.Close)

	client := newFlagTestClient(t, server.URL)
	_, err := client.ListFlags(context.Background())
	failure, ok := domain.AsError(err)
	if !ok || failure.Kind != domain.KindBadGateway {
		t.Fatalf("err = %v, want KindBadGateway", err)
	}
	if failure.Message != "upstream error" {
		t.Fatalf("message = %q, want the generic upstream error", failure.Message)
	}
}
