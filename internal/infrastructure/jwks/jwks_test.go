package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	orbittoken "github.com/manovaspace/orbit-auth/token"
)

func TestLoadReadsAndMarshalsTheKeySet(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "k1.pem"), block, 0o600); err != nil {
		t.Fatal(err)
	}

	doc, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Keys() != 1 {
		t.Fatalf("keys = %d, want 1", doc.Keys())
	}
	var set orbittoken.JWKSet
	if err := json.Unmarshal(doc.Body(), &set); err != nil {
		t.Fatalf("parse document: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "k1" || set.Keys[0].Alg != "RS256" {
		t.Fatalf("document = %+v", set)
	}
	if _, err := set.KeySet(); err != nil {
		t.Fatalf("document does not round-trip: %v", err)
	}
}

func TestLoadFailsWithoutKeys(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("an empty directory was accepted")
	}
}
