package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestKeyFingerprintIsHexAndInputDependent(t *testing.T) {
	at := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	sum := sha256.Sum256([]byte("owner@example.com:123456:" + at.UTC().String()))
	want := hex.EncodeToString(sum[:16])

	got := KeyFingerprint("owner@example.com", "123456", at)
	if got != want {
		t.Fatalf("KeyFingerprint = %q, want %q", got, want)
	}
	if len(got) != 32 {
		t.Fatalf("fingerprint length = %d, want 32", len(got))
	}
	if KeyFingerprint("owner@example.com", "654321", at) == got {
		t.Fatal("a different code produced the same fingerprint")
	}
	if KeyFingerprint("other@example.com", "123456", at) == got {
		t.Fatal("a different email produced the same fingerprint")
	}
	if KeyFingerprint("owner@example.com", "123456", at.Add(time.Second)) == got {
		t.Fatal("a different time produced the same fingerprint")
	}
}

func TestChallengeExpiresInMatchesTheTTL(t *testing.T) {
	if ChallengeTTL != 10*time.Minute {
		t.Fatalf("ChallengeTTL = %s", ChallengeTTL)
	}
	if ChallengeExpiresIn != "10m" {
		t.Fatalf("ChallengeExpiresIn = %q", ChallengeExpiresIn)
	}
}
