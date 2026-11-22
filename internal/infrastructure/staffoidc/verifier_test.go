package staffoidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testIssuer = "https://identity.test/realms/staff"

type audienceEnv struct {
	key *rsa.PrivateKey
	url string
	now time.Time
}

func newAudienceEnv(t *testing.T) audienceEnv {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
		"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(doc)
	}))
	t.Cleanup(srv.Close)
	return audienceEnv{key: key, url: srv.URL, now: time.Now()}
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func (e audienceEnv) verifier(t *testing.T, audiences ...string) *Verifier {
	t.Helper()
	v, err := New(Config{
		Issuer:        testIssuer,
		Audiences:     audiences,
		AllowedGroups: []string{"dev"},
		JWKSURL:       e.url,
		Clock:         fixedClock{now: e.now},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

// token signs a staff token whose aud and azp carry the given values.
func (e audienceEnv) token(t *testing.T, aud any, azp string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":    testIssuer,
		"sub":    "user-1",
		"groups": []string{"dev"},
		"iat":    e.now.Unix(),
		"exp":    e.now.Add(5 * time.Minute).Unix(),
	}
	if aud != nil {
		claims["aud"] = aud
	}
	if azp != "" {
		claims["azp"] = azp
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "k1"
	signed, err := token.SignedString(e.key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestAudienceSingleValue(t *testing.T) {
	env := newAudienceEnv(t)
	v := env.verifier(t, "falak-console")
	if _, err := v.Verify(context.Background(), env.token(t, "account", "falak-console")); err != nil {
		t.Fatalf("azp match: %v", err)
	}
	if _, err := v.Verify(context.Background(), env.token(t, []string{"account", "falak-console"}, "")); err != nil {
		t.Fatalf("aud array match: %v", err)
	}
	if _, err := v.Verify(context.Background(), env.token(t, "other-console", "other-console")); err == nil {
		t.Fatal("token for another client accepted")
	}
}

func TestAudienceList(t *testing.T) {
	env := newAudienceEnv(t)
	v := env.verifier(t, "handbook-ops", " falak-console ", "")
	for name, token := range map[string]string{
		"first audience by azp":  env.token(t, "account", "handbook-ops"),
		"second audience by azp": env.token(t, "account", "falak-console"),
		"second audience by aud": env.token(t, []string{"account", "falak-console"}, ""),
	} {
		if _, err := v.Verify(context.Background(), token); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestAudienceNoneMatches(t *testing.T) {
	env := newAudienceEnv(t)
	v := env.verifier(t, "handbook-ops", "falak-console")
	if _, err := v.Verify(context.Background(), env.token(t, []string{"account"}, "unknown-console")); err == nil {
		t.Fatal("token matching no configured audience accepted")
	}
	if _, err := v.Verify(context.Background(), env.token(t, nil, "")); err == nil {
		t.Fatal("token without aud or azp accepted")
	}
}

func TestAudienceRequiresAtLeastOneValue(t *testing.T) {
	for _, audiences := range [][]string{nil, {}, {""}, {"  "}} {
		if _, err := New(Config{Issuer: testIssuer, Audiences: audiences}); err == nil {
			t.Fatalf("New accepted audiences %q", audiences)
		}
	}
}
