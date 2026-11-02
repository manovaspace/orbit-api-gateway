package domain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// ClaimStatusProvisioned is the status of a completed onboarding claim.
const ClaimStatusProvisioned = "provisioned"

// Workspace defaults returned to a claiming workstation.
const (
	ClaimDefaultEmailDomain   = "manova.space"
	ClaimDefaultManifestScope = "core"
	ClaimGitRemoteBase        = "ssh://git@git.internal.manova.space:2222/manova"
	claimDefaultGroups        = "dev,orbit"
)

// ClaimInput is one workstation onboarding claim.
type ClaimInput struct {
	InviteToken        string
	DesiredUID         string
	Email              string
	DisplayName        string
	SSHPublicKey       string
	MachineFingerprint string
	Scope              string
	Metadata           map[string]string
}

// ClaimUser is the provisioned identity.
type ClaimUser struct {
	UID         string
	Email       string
	DisplayName string
	Groups      []string
}

// ClaimCredentials are the provisioned credentials. WireGuardConfig carries a
// placeholder private key: the gateway never holds a client key.
type ClaimCredentials struct {
	ForgejoUsername string
	ForgejoMCPToken string
	WireGuardConfig string
}

// ClaimWorkspace is the workspace metadata for the claiming workstation.
type ClaimWorkspace struct {
	GitRemoteBase        string
	DefaultManifestScope string
}

// ClaimResult is a completed (or replayed) onboarding claim.
type ClaimResult struct {
	Status           string
	IdempotentReplay bool
	User             ClaimUser
	Credentials      ClaimCredentials
	Workspace        ClaimWorkspace
}

// ClaimCache stores completed claims by idempotency key.
type ClaimCache interface {
	Get(ctx context.Context, key string) (ClaimResult, bool)
	Put(ctx context.Context, key string, result ClaimResult)
}

// NormalizeUID lowercases and trims a requested UID.
func NormalizeUID(uid string) string {
	return strings.ToLower(strings.TrimSpace(uid))
}

// ClaimDefaults fills the email, display name and groups of a claim from its
// UID, keeping every value the caller supplied.
func ClaimDefaults(uid, email, displayName string) (string, string, []string) {
	if email = strings.TrimSpace(email); email == "" {
		email = uid + "@" + ClaimDefaultEmailDomain
	}
	if displayName = strings.TrimSpace(displayName); displayName == "" {
		displayName = cases.Title(language.Und).String(uid)
	}
	return email, displayName, strings.Split(claimDefaultGroups, ",")
}

// ClaimCredentialsFor derives the deterministic credentials of a claim. The
// derived values depend only on the invite token and the UID, so a replay
// returns exactly what the first call returned.
func ClaimCredentialsFor(inviteToken, uid string) ClaimCredentials {
	sum := sha256.Sum256([]byte(inviteToken + ":" + uid))
	return ClaimCredentials{
		ForgejoUsername: uid,
		ForgejoMCPToken: "mcp_" + hex.EncodeToString(sum[:16]),
		WireGuardConfig: wireGuardConfig((int(sum[0]) % 200) + 10),
	}
}

// wireGuardConfig renders the client profile. The private key is a placeholder:
// the gateway cannot see a client key and must not pretend to.
func wireGuardConfig(hostOctet int) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = <generated-client-key>
Address = 10.42.0.%d/32
DNS = 10.42.0.1

[Peer]
PublicKey = 4gZ+examplePublicKeyOrbitGatewayVPNControllerKey=
Endpoint = vpn.internal.manova.space:51820
AllowedIPs = 10.42.0.0/16, 172.28.0.0/16
PersistentKeepalive = 25`, hostOctet)
}
