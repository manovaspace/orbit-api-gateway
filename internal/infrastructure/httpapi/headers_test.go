package httpapi

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

// TestRateLimitHeaderSpelling reads the raw response bytes. Go's HTTP client
// canonicalises header names on parse, so only a raw connection can prove the
// edge still writes "X-RateLimit-Limit" rather than fasthttp's
// "X-Ratelimit-Limit".
func TestRateLimitHeaderSpelling(t *testing.T) {
	env := newContractEnv(t, contractConfig{})

	conn, err := net.Dial("tcp", strings.TrimPrefix(env.main, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	body := `{"identifier":"person@example.com","password":"wrong"}`
	request := fmt.Sprintf("POST /api/v1/auth/login HTTP/1.1\r\nHost: gateway\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}

	for _, header := range []string{"X-RateLimit-Limit: 10", "X-RateLimit-Remaining: 9", "X-RateLimit-Reset: "} {
		if !bytes.Contains(raw, []byte(header)) {
			t.Fatalf("response does not contain %q:\n%s", header, raw)
		}
	}
	if bytes.Contains(raw, []byte("X-Ratelimit-")) {
		t.Fatalf("response uses the canonicalised spelling:\n%s", raw)
	}
}
