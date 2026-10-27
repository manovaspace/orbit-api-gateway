package httpapi

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	orbittoken "github.com/manovaspace/orbit-auth/token"
)

func TestServeJWKS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(nil, nil)
	srv.ServeJWKS(orbittoken.KeySet{"k1": &key.PublicKey})

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var doc orbittoken.JWKSet
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 1 || doc.Keys[0].KeyID != "k1" || doc.Keys[0].Alg != "RS256" {
		t.Fatalf("unexpected document: %+v", doc)
	}
	if _, err := doc.KeySet(); err != nil {
		t.Fatalf("document does not round-trip: %v", err)
	}
}
