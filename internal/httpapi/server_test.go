package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServer_InstallerEndpoints(t *testing.T) {
	srv := NewServer(nil, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	t.Run("GET /", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/")
		if err != nil {
			t.Fatalf("GET / failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", resp.StatusCode)
		}

		ct := resp.Header.Get("Content-Type")
		if ct != "text/x-shellscript; charset=utf-8" {
			t.Errorf("expected Content-Type 'text/x-shellscript; charset=utf-8', got %q", ct)
		}

		cc := resp.Header.Get("Cache-Control")
		if cc != "no-cache, no-store, must-revalidate" {
			t.Errorf("expected Cache-Control 'no-cache, no-store, must-revalidate', got %q", cc)
		}

		var buf bytes.Buffer
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			t.Fatalf("failed reading body: %v", err)
		}
		body := buf.String()

		if !strings.HasPrefix(body, "#!/usr/bin/env bash") {
			t.Errorf("expected bash shebang, got %q", body[:min(len(body), 50)])
		}

		// Verify interactive confirmation prompt is present
		if !strings.Contains(body, "Do you want to proceed with the installation?") {
			t.Errorf("expected interactive installation prompt in script")
		}

		// Verify binary symlink shortcut is present
		if !strings.Contains(body, "(binary symlink)") {
			t.Errorf("expected binary symlink shortcut in script")
		}
	})
}

func TestServer_UnmappedRoutes(t *testing.T) {
	srv := NewServer(nil, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	unmapped := []string{
		"/install",
		"/install.sh",
		"/unknown",
		"/install.py",
		"/api/v1/nonexistent",
		"/installer",
		"/install/more",
	}

	for _, path := range unmapped {
		t.Run("GET "+path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + path)
			if err != nil {
				t.Fatalf("GET %s failed: %v", path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("expected 404 Not Found for %s, got %d", path, resp.StatusCode)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
