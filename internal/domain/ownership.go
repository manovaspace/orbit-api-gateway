package domain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// ChallengeTTL is how long an ownership challenge code stays valid.
const ChallengeTTL = 10 * time.Minute

// ChallengeExpiresIn is the wire value the challenge response publishes for
// ChallengeTTL. It is a string, not time.Duration.String(), which would render
// "10m0s" and change the contract.
const ChallengeExpiresIn = "10m"

// Response statuses of the ownership routes.
const (
	ChallengeStatusDispatched = "challenge_dispatched"
	ProofStatusVerified       = "verified"
)

// Challenge is one in-flight ownership code.
type Challenge struct {
	Code      string
	ExpiresAt time.Time
}

// ChallengeGrant is the response of a dispatched challenge.
type ChallengeGrant struct {
	Status    string
	ExpiresIn string
}

// OwnershipProof is the response of a verified challenge. KeyFingerprint is a
// proof of the exchange, not a signing secret.
type OwnershipProof struct {
	Status         string
	Email          string
	DisplayName    string
	KeyFingerprint string
	VerifiedAt     time.Time
}

// ChallengeStore keeps in-flight challenges. The application layer owns the
// rules; the store owns only the atomicity of compare-and-remove.
type ChallengeStore interface {
	Save(ctx context.Context, email string, challenge Challenge)
	// Confirm returns the stored challenge and removes it when accept returns
	// true. A rejected challenge stays stored, so a wrong code can be retried.
	Confirm(ctx context.Context, email string, accept func(Challenge) bool) (Challenge, bool)
}

// KeyFingerprint derives the 16-byte SHA-256 fingerprint the verify response
// returns: hex(sha256(email:code:time)[:16]).
func KeyFingerprint(email, code string, at time.Time) string {
	sum := sha256.Sum256([]byte(email + ":" + code + ":" + at.UTC().String()))
	return hex.EncodeToString(sum[:16])
}
