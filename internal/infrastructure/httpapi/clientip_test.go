package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func mustTrusted(t *testing.T, raw string) []netip.Prefix {
	t.Helper()
	prefixes, err := ParseTrustedProxies(raw)
	if err != nil {
		t.Fatal(err)
	}
	return prefixes
}

func TestClientAddrIP(t *testing.T) {
	docker := clientAddr{trusted: mustTrusted(t, "172.16.0.0/12")}
	ipv6 := clientAddr{trusted: mustTrusted(t, "fd00::/8")}
	trustAll := clientAddr{trustAll: true}

	tests := []struct {
		name   string
		client clientAddr
		remote string
		xff    []string
		want   string
	}{
		{"untrusted socket ignores spoofed header", docker, "203.0.113.50:1234", []string{"198.51.100.1"}, "203.0.113.50"},
		{"trusted socket takes header", docker, "172.18.0.5:1234", []string{"203.0.113.9"}, "203.0.113.9"},
		{"rightmost untrusted wins over left spoof", docker, "172.18.0.5:1234", []string{"198.51.100.7, 203.0.113.9"}, "203.0.113.9"},
		{"chain through another trusted proxy", docker, "172.18.0.5:1234", []string{"203.0.113.9, 172.18.0.3"}, "203.0.113.9"},
		{"all hops trusted falls back to socket", docker, "172.18.0.5:1234", []string{"172.18.0.3, 172.17.0.2"}, "172.18.0.5"},
		{"malformed header falls back to socket", docker, "172.18.0.5:1234", []string{"garbage"}, "172.18.0.5"},
		{"malformed entry on the right stops the walk", docker, "172.18.0.5:1234", []string{"198.51.100.7, garbage, 172.18.0.3"}, "172.18.0.5"},
		{"empty header value falls back to socket", docker, "172.18.0.5:1234", []string{""}, "172.18.0.5"},
		{"no header falls back to socket", docker, "172.18.0.5:1234", nil, "172.18.0.5"},
		{"two header lines combine in order", docker, "172.18.0.5:1234", []string{"198.51.100.7", "203.0.113.9, 172.18.0.3"}, "203.0.113.9"},
		{"two header lines, trusted tail", docker, "172.18.0.5:1234", []string{"203.0.113.9", "172.18.0.3"}, "203.0.113.9"},
		{"ipv6 trusted prefix and ipv6 client", ipv6, "[fd00::5]:1234", []string{"2001:DB8::9"}, "2001:db8::9"},
		{"ipv6 client through ipv4 proxy", docker, "172.18.0.5:1234", []string{"2001:DB8::9"}, "2001:db8::9"},
		{"ipv4-mapped socket is treated as ipv4", docker, "[::ffff:172.18.0.5]:1234", []string{"203.0.113.9"}, "203.0.113.9"},
		{"ipv4-mapped untrusted socket is unmapped", docker, "[::ffff:203.0.113.50]:1234", []string{"198.51.100.1"}, "203.0.113.50"},
		{"trust all keeps first entry", trustAll, "198.51.100.2:1", []string{"203.0.113.9, 172.18.0.3"}, "203.0.113.9"},
		{"trust all without header uses socket", trustAll, "198.51.100.2:1", nil, "198.51.100.2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			r.RemoteAddr = tc.remote
			for _, value := range tc.xff {
				r.Header.Add("X-Forwarded-For", value)
			}
			if got := tc.client.ip(r); got != tc.want {
				t.Fatalf("ip() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseTrustedProxies(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    []string
		wantErr string
	}{
		{name: "cidr and bare ip", raw: "172.16.0.0/12, 10.0.0.1", want: []string{"172.16.0.0/12", "10.0.0.1/32"}},
		{name: "empty", raw: "", want: nil},
		{name: "blank items skipped", raw: " , ", want: nil},
		{name: "ipv6", raw: "fd00::/8,::1", want: []string{"fd00::/8", "::1/128"}},
		{name: "invalid item named", raw: "nope", wantErr: "nope"},
		{name: "invalid prefix length", raw: "10.0.0.0/33", wantErr: "10.0.0.0/33"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTrustedProxies(tc.raw)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var strs []string
			for _, p := range got {
				strs = append(strs, p.String())
			}
			if !reflect.DeepEqual(strs, tc.want) {
				t.Fatalf("prefixes = %v, want %v", strs, tc.want)
			}
		})
	}
}
