package httpapi

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ParseTrustedProxies parses RATE_LIMIT_TRUSTED_PROXIES: comma-separated CIDRs
// or bare IPs (a bare IP is a /32 or /128). Empty items are skipped. Any
// invalid item is an error that names it.
func ParseTrustedProxies(raw string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			prefix, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("RATE_LIMIT_TRUSTED_PROXIES: invalid CIDR %q: %w", item, err)
			}
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("RATE_LIMIT_TRUSTED_PROXIES: invalid address %q: %w", item, err)
		}
		addr = addr.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

// clientAddr decides which address the rate limiter buckets on.
type clientAddr struct {
	// trustAll reads the first X-Forwarded-For entry from every peer. It is
	// the deprecated RATE_LIMIT_TRUST_PROXY behaviour.
	trustAll bool
	// trusted lists the peers whose X-Forwarded-For is believed.
	trusted []netip.Prefix
}

// ip returns the client address for r. An untrusted socket address is returned
// as-is and its X-Forwarded-For is ignored. From a trusted peer, the chain is
// walked from the right: trusted hops are skipped and the first untrusted
// address is the client. A malformed chain falls back to the socket address.
func (c clientAddr) ip(r *http.Request) string {
	addr, text := remoteAddr(r.RemoteAddr)
	if c.trustAll {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			return strings.TrimSpace(strings.Split(forwarded, ",")[0])
		}
		return text
	}
	if !c.contains(addr) {
		return text
	}
	var entries []string
	for _, value := range r.Header.Values("X-Forwarded-For") {
		for _, item := range strings.Split(value, ",") {
			entries = append(entries, strings.TrimSpace(item))
		}
	}
	for i := len(entries) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(entries[i])
		if err != nil {
			return text
		}
		hop = hop.Unmap()
		if c.contains(hop) {
			continue
		}
		return hop.String()
	}
	return text
}

// contains reports whether addr falls in a trusted prefix. An invalid address
// is never trusted.
func (c clientAddr) contains(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	for _, prefix := range c.trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// remoteAddr parses the socket address. It returns the unmapped address when
// the socket is a valid IP, and the raw host text otherwise.
func remoteAddr(remote string) (netip.Addr, string) {
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		addr := ap.Addr().Unmap()
		return addr, addr.String()
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		return addr, addr.String()
	}
	return netip.Addr{}, host
}
