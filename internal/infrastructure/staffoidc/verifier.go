// Package staffoidc verifies the Keycloak access tokens staff sign in with. The
// staff realm publishes RS256 keys at a JWKS URL; the verifier caches them and
// accepts a token only when its issuer, audience, expiry and staff group all
// check out.
package staffoidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultCacheTTL    = 10 * time.Minute
	defaultHTTPTimeout = 5 * time.Second
	// refetchInterval bounds JWKS fetches: an unknown kid, an expired cache or
	// a failed fetch never triggers another fetch sooner than this.
	refetchInterval = 30 * time.Second
	clockLeeway     = 30 * time.Second
	maxJWKSBytes    = 1 << 20
)

// ErrNoAllowedGroups is returned when the verifier has no group configured. It
// refuses every token: fail closed.
var ErrNoAllowedGroups = errors.New("staffoidc: no allowed groups configured")

// ErrNotAllowed is returned for a valid token that carries no allowed group.
var ErrNotAllowed = errors.New("staffoidc: token has no allowed group")

// ErrUnknownKey is returned when the token's kid is not in the JWKS.
var ErrUnknownKey = errors.New("staffoidc: unknown signing key")

// Clock supplies the current time. Tests inject a fake.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Config configures a Verifier.
type Config struct {
	// Issuer is the exact iss the token must carry, for example
	// https://identity.internal.manova.space/realms/staff.
	Issuer string
	// Audience is the console client id. It matches an aud entry (string or
	// array) or the azp claim.
	Audience string
	// AllowedGroups lists the staff groups. A leading slash is ignored on both
	// sides, so "dev" and "/dev" match the same group.
	AllowedGroups []string
	// JWKSURL defaults to Issuer + "/protocol/openid-connect/certs".
	JWKSURL string
	// HTTPClient defaults to a client with a 5 second timeout.
	HTTPClient *http.Client
	// CacheTTL defaults to 10 minutes.
	CacheTTL time.Duration
	// Clock defaults to the system clock.
	Clock Clock
}

// Identity is the verified staff person.
type Identity struct {
	Subject           string
	PreferredUsername string
	Email             string
	Groups            []string
}

// Verifier checks Keycloak access tokens. It is safe for concurrent use.
type Verifier struct {
	issuer   string
	audience string
	jwksURL  string
	allowed  map[string]struct{}
	client   *http.Client
	ttl      time.Duration
	clock    Clock

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	expiresAt   time.Time
	lastAttempt time.Time
}

// New validates cfg and returns a Verifier.
func New(cfg Config) (*Verifier, error) {
	issuer := strings.TrimSpace(cfg.Issuer)
	audience := strings.TrimSpace(cfg.Audience)
	if issuer == "" {
		return nil, errors.New("staffoidc: issuer is required")
	}
	if audience == "" {
		return nil, errors.New("staffoidc: audience is required")
	}
	jwksURL := strings.TrimSpace(cfg.JWKSURL)
	if jwksURL == "" {
		jwksURL = strings.TrimSuffix(issuer, "/") + "/protocol/openid-connect/certs"
	}
	allowed := make(map[string]struct{}, len(cfg.AllowedGroups))
	for _, group := range cfg.AllowedGroups {
		if name := normalizeGroup(group); name != "" {
			allowed[name] = struct{}{}
		}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	clock := cfg.Clock
	if clock == nil {
		clock = systemClock{}
	}
	return &Verifier{
		issuer:   issuer,
		audience: audience,
		jwksURL:  jwksURL,
		allowed:  allowed,
		client:   client,
		ttl:      ttl,
		clock:    clock,
	}, nil
}

// Verify parses raw and returns the staff identity it carries. Any failure is
// an error; the identity is returned only when every check passes.
func (v *Verifier) Verify(ctx context.Context, raw string) (Identity, error) {
	if len(v.allowed) == 0 {
		return Identity{}, ErrNoAllowedGroups
	}
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(clockLeeway),
		jwt.WithTimeFunc(v.clock.Now),
	)
	_, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, ErrUnknownKey
		}
		return v.key(ctx, kid)
	})
	if err != nil {
		return Identity{}, fmt.Errorf("staffoidc: parse token: %w", err)
	}
	if !audienceMatches(claims, v.audience) {
		return Identity{}, errors.New("staffoidc: audience mismatch")
	}
	subject, _ := claims["sub"].(string)
	if subject == "" {
		return Identity{}, errors.New("staffoidc: token has no subject")
	}
	groups := groupsClaim(claims)
	if !v.inAllowedGroup(groups) {
		return Identity{}, ErrNotAllowed
	}
	preferred, _ := claims["preferred_username"].(string)
	email, _ := claims["email"].(string)
	return Identity{Subject: subject, PreferredUsername: preferred, Email: email, Groups: groups}, nil
}

func (v *Verifier) inAllowedGroup(groups []string) bool {
	for _, group := range groups {
		if _, ok := v.allowed[group]; ok {
			return true
		}
	}
	return false
}

// key returns the RSA key for kid. It serves from the cache while the cache is
// fresh; otherwise it fetches the JWKS, at most once per refetchInterval.
func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := v.clock.Now()
	if v.keys != nil && now.Before(v.expiresAt) {
		if key, ok := v.keys[kid]; ok {
			return key, nil
		}
	}
	if now.Sub(v.lastAttempt) < refetchInterval {
		return nil, ErrUnknownKey
	}

	// A caller that disconnects must not cancel the shared fetch: a cancelled
	// attempt would still count against refetchInterval and block every caller.
	keys, err := v.fetchJWKS(context.WithoutCancel(ctx))
	v.lastAttempt = now
	if err != nil {
		return nil, err
	}
	v.keys = keys
	v.expiresAt = now.Add(v.ttl)
	key, ok := keys[kid]
	if !ok {
		return nil, ErrUnknownKey
	}
	return key, nil
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// fetchJWKS downloads the key set and keeps the RSA signing keys that have a kid.
func (v *Verifier) fetchJWKS(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("staffoidc: jwks request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("staffoidc: fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("staffoidc: fetch jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("staffoidc: read jwks: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return nil, errors.New("staffoidc: jwks document too large")
	}
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("staffoidc: decode jwks: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Alg != "" && k.Alg != "RS256" {
			continue
		}
		key, ok := rsaKey(k)
		if ok {
			keys[k.Kid] = key
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("staffoidc: jwks has no RSA signing keys")
	}
	return keys, nil
}

func rsaKey(k jwk) (*rsa.PublicKey, bool) {
	nb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.N, "="))
	if err != nil || len(nb) == 0 {
		return nil, false
	}
	eb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.E, "="))
	if err != nil || len(eb) == 0 {
		return nil, false
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() || e.Int64() < 3 {
		return nil, false
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}, true
}

func audienceMatches(claims jwt.MapClaims, audience string) bool {
	if azp, _ := claims["azp"].(string); azp == audience {
		return true
	}
	switch aud := claims["aud"].(type) {
	case string:
		return aud == audience
	case []any:
		for _, item := range aud {
			if s, ok := item.(string); ok && s == audience {
				return true
			}
		}
	}
	return false
}

func groupsClaim(claims jwt.MapClaims) []string {
	raw, _ := claims["groups"].([]any)
	groups := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			if name := normalizeGroup(s); name != "" {
				groups = append(groups, name)
			}
		}
	}
	return groups
}

// normalizeGroup trims space and one leading slash, so "/dev" and "dev" compare
// equal.
func normalizeGroup(group string) string {
	return strings.TrimPrefix(strings.TrimSpace(group), "/")
}
