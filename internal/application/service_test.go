package application

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

func TestRequestOTPReportsTheIdentifierBudget(t *testing.T) {
	svc, auth, limiter, _, _ := testService(t, nil)

	receipt, err := svc.RequestOTP(context.Background(), domain.OTPRequest{
		Identifier:    "Person@Example.com",
		Channel:       "email",
		Email:         "legacy@example.com",
		CorrelationID: "c-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ExpiresAt != "2026-08-30T23:00:00Z" {
		t.Fatalf("expires_at = %q", receipt.ExpiresAt)
	}
	if receipt.IdentifierLimit == nil || receipt.IdentifierLimit.Limit != 5 || receipt.IdentifierLimit.Remaining != 4 {
		t.Fatalf("identifier limit = %+v", receipt.IdentifierLimit)
	}
	if len(limiter.keys) != 1 || limiter.keys[0] != domain.IdentifierKey("Person@Example.com") {
		t.Fatalf("limiter keys = %v", limiter.keys)
	}
	if got := limiter.policies[0]; got != domain.OTPRequestIdentifierPolicy() {
		t.Fatalf("policy = %+v", got)
	}
	if len(auth.requestSeen) != 1 {
		t.Fatalf("upstream calls = %d", len(auth.requestSeen))
	}
	seen := auth.requestSeen[0]
	if seen.Identifier != "Person@Example.com" || seen.Channel != "email" ||
		seen.Email != "legacy@example.com" || seen.CorrelationID != "c-1" {
		t.Fatalf("upstream request = %+v", seen)
	}
}

func TestRequestOTPFallsBackToEmail(t *testing.T) {
	svc, _, limiter, _, _ := testService(t, nil)

	if _, err := svc.RequestOTP(context.Background(), domain.OTPRequest{Email: "legacy@example.com"}); err != nil {
		t.Fatal(err)
	}
	if len(limiter.keys) != 1 || limiter.keys[0] != domain.IdentifierKey("legacy@example.com") {
		t.Fatalf("limiter keys = %v", limiter.keys)
	}
}

func TestRequestOTPWithoutIdentifierSkipsTheIdentifierBucket(t *testing.T) {
	svc, _, limiter, _, _ := testService(t, nil)

	receipt, err := svc.RequestOTP(context.Background(), domain.OTPRequest{Channel: "email"})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.IdentifierLimit != nil {
		t.Fatalf("identifier limit = %+v, want none", receipt.IdentifierLimit)
	}
	if len(limiter.keys) != 0 {
		t.Fatalf("limiter was called with %v", limiter.keys)
	}
}

func TestRequestOTPStopsBeforeUpstreamWhenTheIdentifierIsLimited(t *testing.T) {
	svc, auth, limiter, _, _ := testService(t, nil)
	limiter.decision = domain.Decision{Allowed: false, Limit: 3, Remaining: 0}

	_, err := svc.RequestOTP(context.Background(), domain.OTPRequest{Identifier: "person@example.com"})
	var limit *domain.LimitError
	if !errors.As(err, &limit) || limit.Unavailable {
		t.Fatalf("err = %v, want a denial", err)
	}
	if limit.Decision.Limit != 3 {
		t.Fatalf("decision = %+v", limit.Decision)
	}
	if len(auth.requestSeen) != 0 {
		t.Fatalf("upstream was called %d times", len(auth.requestSeen))
	}
}

func TestRequestOTPReportsAnUnavailableLimiter(t *testing.T) {
	svc, auth, limiter, _, _ := testService(t, nil)
	limiter.err = errors.New("redis down")

	_, err := svc.RequestOTP(context.Background(), domain.OTPRequest{Identifier: "person@example.com"})
	var limit *domain.LimitError
	if !errors.As(err, &limit) || !limit.Unavailable {
		t.Fatalf("err = %v, want an unavailable limiter", err)
	}
	if len(auth.requestSeen) != 0 {
		t.Fatalf("upstream was called %d times", len(auth.requestSeen))
	}
}

func TestRequestOTPPassesUpstreamFailuresThrough(t *testing.T) {
	svc, _, _, _, _ := testService(t, func(_ *Deps, auth *fakeAuth, _ *fakeLimiter) {
		auth.requestOTP = func(domain.OTPRequest) (string, error) {
			return "", domain.NewError(domain.KindInvalidArgument, "bad identifier")
		}
	})

	_, err := svc.RequestOTP(context.Background(), domain.OTPRequest{Identifier: "x"})
	failure, ok := domain.AsError(err)
	if !ok || failure.Kind != domain.KindInvalidArgument || failure.Message != "bad identifier" {
		t.Fatalf("err = %v", err)
	}
}

func TestLoginIdentifierPrecedence(t *testing.T) {
	tests := []struct {
		name string
		in   domain.PasswordLogin
		want string
	}{
		{"identifier wins", domain.PasswordLogin{Identifier: "+989121234567", Email: "user@example.com", Password: "p"}, "+989121234567"},
		{"email is the fallback", domain.PasswordLogin{Email: "user@example.com", Password: "p"}, "user@example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, auth, _, _, _ := testService(t, nil)
			if _, err := svc.Login(context.Background(), tc.in); err != nil {
				t.Fatal(err)
			}
			if len(auth.loginSeen) != 1 {
				t.Fatalf("upstream calls = %d", len(auth.loginSeen))
			}
			if got := auth.loginSeen[0]; got.Identifier != tc.want || got.Password != "p" {
				t.Fatalf("upstream request = %+v, want identifier %q", got, tc.want)
			}
		})
	}
}

func TestVerifyRefreshAndValidateForwardToThePort(t *testing.T) {
	svc, auth, _, _, _ := testService(t, nil)
	ctx := context.Background()

	if _, err := svc.VerifyOTP(ctx, domain.OTPVerification{Identifier: "p", Code: "123456"}); err != nil {
		t.Fatal(err)
	}
	if len(auth.verifySeen) != 1 || auth.verifySeen[0].Code != "123456" {
		t.Fatalf("verify calls = %+v", auth.verifySeen)
	}
	if _, err := svc.RefreshToken(ctx, "refresh-token"); err != nil {
		t.Fatal(err)
	}
	if len(auth.refreshSeen) != 1 || auth.refreshSeen[0] != "refresh-token" {
		t.Fatalf("refresh calls = %+v", auth.refreshSeen)
	}
	identity, err := svc.ValidateAPIToken(ctx, "oat_x")
	if err != nil {
		t.Fatal(err)
	}
	if identity.UserID != "user" {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestChallengeStoresTheCodeAndExpiry(t *testing.T) {
	svc, _, limiter, challenges, _ := testService(t, nil)

	receipt, err := svc.Challenge(context.Background(), " Owner@Example.com ")
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Grant.Status != domain.ChallengeStatusDispatched || receipt.Grant.ExpiresIn != "10m" {
		t.Fatalf("grant = %+v", receipt.Grant)
	}
	if receipt.IdentifierLimit == nil || receipt.IdentifierLimit.Limit != 5 {
		t.Fatalf("identifier limit = %+v", receipt.IdentifierLimit)
	}
	stored, ok := challenges.items["owner@example.com"]
	if !ok {
		t.Fatalf("challenge keys = %v", challenges.items)
	}
	if stored.Code != "123456" {
		t.Fatalf("code = %q", stored.Code)
	}
	if want := testNow.Add(domain.ChallengeTTL); !stored.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at = %s, want %s", stored.ExpiresAt, want)
	}
	if len(limiter.keys) != 1 || limiter.keys[0] != domain.IdentifierKey("owner@example.com") {
		t.Fatalf("limiter keys = %v", limiter.keys)
	}
}

func TestChallengeRejectsABadEmailBeforeLimiting(t *testing.T) {
	svc, _, limiter, challenges, _ := testService(t, nil)

	_, err := svc.Challenge(context.Background(), "not-an-email")
	failure, ok := domain.AsError(err)
	if !ok || failure.Kind != domain.KindInvalidArgument || failure.Message != "valid email is required" {
		t.Fatalf("err = %v", err)
	}
	if len(limiter.keys) != 0 {
		t.Fatalf("limiter was called with %v", limiter.keys)
	}
	if len(challenges.items) != 0 {
		t.Fatalf("challenge was stored")
	}
}

func TestChallengeStopsWhenTheIdentifierIsLimited(t *testing.T) {
	svc, _, limiter, challenges, _ := testService(t, nil)
	limiter.decision = domain.Decision{Allowed: false, Limit: 3}

	_, err := svc.Challenge(context.Background(), "owner@example.com")
	var limit *domain.LimitError
	if !errors.As(err, &limit) {
		t.Fatalf("err = %v, want a denial", err)
	}
	if len(challenges.items) != 0 {
		t.Fatalf("challenge was stored")
	}
}

func TestVerifyChallengeConsumesTheCodeOnce(t *testing.T) {
	svc, _, _, challenges, _ := testService(t, nil)
	ctx := context.Background()
	challenges.Save(ctx, "owner@example.com", domain.Challenge{
		Code:      "123456",
		ExpiresAt: testNow.Add(domain.ChallengeTTL),
	})

	proof, err := svc.VerifyChallenge(ctx, " OWNER@example.com ", " 123456 ")
	if err != nil {
		t.Fatal(err)
	}
	if proof.Status != domain.ProofStatusVerified || proof.Email != "owner@example.com" {
		t.Fatalf("proof = %+v", proof)
	}
	if !proof.VerifiedAt.Equal(testNow) {
		t.Fatalf("verified_at = %s", proof.VerifiedAt)
	}
	if want := domain.KeyFingerprint("owner@example.com", "123456", testNow); proof.KeyFingerprint != want {
		t.Fatalf("fingerprint = %q, want %q", proof.KeyFingerprint, want)
	}
	if _, ok := challenges.items["owner@example.com"]; ok {
		t.Fatal("challenge was not consumed")
	}

	_, err = svc.VerifyChallenge(ctx, "owner@example.com", "123456")
	failure, ok := domain.AsError(err)
	if !ok || failure.Kind != domain.KindUnauthenticated || failure.Message != "invalid or expired verification code" {
		t.Fatalf("second verify err = %v", err)
	}
}

func TestVerifyChallengeKeepsTheCodeAfterAWrongAttempt(t *testing.T) {
	svc, _, _, challenges, _ := testService(t, nil)
	ctx := context.Background()
	challenges.Save(ctx, "owner@example.com", domain.Challenge{
		Code:      "123456",
		ExpiresAt: testNow.Add(domain.ChallengeTTL),
	})

	if _, err := svc.VerifyChallenge(ctx, "owner@example.com", "000000"); err == nil {
		t.Fatal("a wrong code was accepted")
	}
	if _, ok := challenges.items["owner@example.com"]; !ok {
		t.Fatal("a wrong code consumed the challenge")
	}
	if _, err := svc.VerifyChallenge(ctx, "owner@example.com", "123456"); err != nil {
		t.Fatalf("retry with the right code: %v", err)
	}
}

func TestVerifyChallengeRejectsAnExpiredCode(t *testing.T) {
	clock := &fakeClock{now: testNow}
	svc, _, _, challenges, _ := testService(t, func(deps *Deps, _ *fakeAuth, _ *fakeLimiter) {
		deps.Clock = clock
	})
	ctx := context.Background()
	challenges.Save(ctx, "owner@example.com", domain.Challenge{
		Code:      "123456",
		ExpiresAt: testNow.Add(domain.ChallengeTTL),
	})

	clock.now = testNow.Add(domain.ChallengeTTL + time.Second)
	_, err := svc.VerifyChallenge(ctx, "owner@example.com", "123456")
	failure, ok := domain.AsError(err)
	if !ok || failure.Kind != domain.KindUnauthenticated {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyChallengeRequiresBothFields(t *testing.T) {
	svc, _, _, _, _ := testService(t, nil)

	for _, tc := range []struct{ email, code string }{{"", "123456"}, {"owner@example.com", ""}, {" ", " "}} {
		_, err := svc.VerifyChallenge(context.Background(), tc.email, tc.code)
		failure, ok := domain.AsError(err)
		if !ok || failure.Kind != domain.KindInvalidArgument || failure.Message != "email and code are required" {
			t.Fatalf("err for %q/%q = %v", tc.email, tc.code, err)
		}
	}
}

func TestCheckClassLimitUsesThePolicyForItsClass(t *testing.T) {
	svc, _, limiter, _, _ := testService(t, nil)

	decision, err := svc.CheckClassLimit(context.Background(), domain.ClassAuthPassword, "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if decision.Limit != 5 {
		t.Fatalf("decision = %+v", decision)
	}
	if len(limiter.keys) != 1 || limiter.keys[0] != "rl:auth_password:203.0.113.9" {
		t.Fatalf("limiter keys = %v", limiter.keys)
	}
	if want := domain.PolicyFor(domain.ClassAuthPassword); limiter.policies[0] != want {
		t.Fatalf("policy = %+v, want %+v", limiter.policies[0], want)
	}
}

func TestCheckClassLimitOnAnUnpolicedClassKeepsTheZeroPolicy(t *testing.T) {
	svc, _, limiter, _, _ := testService(t, nil)

	if _, err := svc.CheckClassLimit(context.Background(), domain.ClassOwnershipChallenge, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if got := limiter.policies[0]; got != (domain.Policy{}) {
		t.Fatalf("policy = %+v, want the zero policy", got)
	}
}

func TestCheckClassLimitReportsDenialAndUnavailability(t *testing.T) {
	svc, _, limiter, _, _ := testService(t, nil)
	limiter.decision = domain.Decision{Allowed: false, RetryAfter: 7 * time.Second}

	_, err := svc.CheckClassLimit(context.Background(), domain.ClassAuthPassword, "127.0.0.1")
	var limit *domain.LimitError
	if !errors.As(err, &limit) || limit.Unavailable || limit.Decision.RetryAfter != 7*time.Second {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "rate limit exceeded") {
		t.Fatalf("message = %q", err.Error())
	}

	limiter.err = errors.New("redis down")
	_, err = svc.CheckClassLimit(context.Background(), domain.ClassAuthPassword, "127.0.0.1")
	if !errors.As(err, &limit) || !limit.Unavailable {
		t.Fatalf("err = %v", err)
	}
}

func TestClaimDerivesTheDocumentedCredentials(t *testing.T) {
	svc, _, _, _, claims := testService(t, nil)

	result, err := svc.Claim(context.Background(), domain.ClaimInput{
		InviteToken: "tok-1",
		DesiredUID:  " John ",
		Email:       "john@example.com",
		DisplayName: "John Doe",
	}, "idem-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.ClaimStatusProvisioned || result.IdempotentReplay {
		t.Fatalf("result = %+v", result)
	}
	if result.User.UID != "john" || result.User.Email != "john@example.com" || result.User.DisplayName != "John Doe" {
		t.Fatalf("user = %+v", result.User)
	}
	if len(result.User.Groups) != 2 || result.User.Groups[0] != "dev" || result.User.Groups[1] != "orbit" {
		t.Fatalf("groups = %v", result.User.Groups)
	}
	if result.Credentials.ForgejoUsername != "john" {
		t.Fatalf("forgejo username = %q", result.Credentials.ForgejoUsername)
	}
	if result.Credentials.ForgejoMCPToken != "mcp_f3bc3d3c17133acba84bdcefa610add1" {
		t.Fatalf("mcp token = %q", result.Credentials.ForgejoMCPToken)
	}
	if !strings.Contains(result.Credentials.WireGuardConfig, "Address = 10.42.0.53/32") {
		t.Fatalf("wireguard config = %q", result.Credentials.WireGuardConfig)
	}
	if _, ok := claims.items["idem-1"]; !ok {
		t.Fatalf("claim keys = %v", claims.items)
	}
}

func TestClaimReplaysByIdempotencyKeyOrDerivedKey(t *testing.T) {
	svc, _, _, _, claims := testService(t, nil)
	in := domain.ClaimInput{InviteToken: "tok-1", DesiredUID: "john"}

	first, err := svc.Claim(context.Background(), in, "idem-1")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := svc.Claim(context.Background(), in, "idem-1")
	if err != nil {
		t.Fatal(err)
	}
	if !replay.IdempotentReplay || replay.Credentials != first.Credentials {
		t.Fatalf("replay = %+v", replay)
	}
	if _, ok := claims.items["tok-1:john"]; ok {
		t.Fatal("the derived key was used even though a header key was supplied")
	}

	// Without a header the derived token:uid key replays the same claim.
	if _, err := svc.Claim(context.Background(), in, "idem-1"); err != nil {
		t.Fatal(err)
	}
	derived, err := svc.Claim(context.Background(), domain.ClaimInput{InviteToken: "tok-2", DesiredUID: "jane"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if derived.IdempotentReplay {
		t.Fatal("a new claim replayed another claim")
	}
	second, err := svc.Claim(context.Background(), domain.ClaimInput{InviteToken: "tok-2", DesiredUID: "jane"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !second.IdempotentReplay {
		t.Fatalf("second claim = %+v", second)
	}
}

func TestClaimRequiresTokenAndUID(t *testing.T) {
	svc, _, _, _, _ := testService(t, nil)

	for _, tc := range []domain.ClaimInput{{}, {InviteToken: "tok"}, {DesiredUID: "john"}, {InviteToken: " ", DesiredUID: "john"}} {
		_, err := svc.Claim(context.Background(), tc, "")
		failure, ok := domain.AsError(err)
		if !ok || failure.Kind != domain.KindInvalidArgument || failure.Message != "invite_token and desired_uid are required" {
			t.Fatalf("err for %+v = %v", tc, err)
		}
	}
}

func TestAssetsAreServedThroughThePort(t *testing.T) {
	svc, _, _, _, _ := testService(t, nil)

	if got := string(svc.InstallScript()); got != "#!/bin/sh\n" {
		t.Fatalf("install script = %q", got)
	}
	if body, err := svc.OpenAPISpec(); err != nil || string(body) != "openapi: 3.1.0\n" {
		t.Fatalf("spec = %q, %v", body, err)
	}
	if body, err := svc.Manifest(); err != nil || string(body) != "{}\n" {
		t.Fatalf("manifest = %q, %v", body, err)
	}
}

func TestListFlagsForwardsToThePort(t *testing.T) {
	want := domain.FlagSet{
		Version: "2026-11-03T10:00:00Z",
		Flags:   []domain.FeatureFlag{{Name: "beta", Enabled: true, Description: "Beta access"}},
	}
	svc, _, _, _, _ := testService(t, func(deps *Deps, _ *fakeAuth, _ *fakeLimiter) {
		deps.Flags = fakeFlags{set: want}
	})

	got, err := svc.ListFlags(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != want.Version || len(got.Flags) != 1 || got.Flags[0] != want.Flags[0] {
		t.Fatalf("ListFlags = %+v, want %+v", got, want)
	}
}

func TestServiceReportsMissingPorts(t *testing.T) {
	svc := NewService(Deps{})
	if svc.HasAuth() || svc.HasLimiter() {
		t.Fatal("empty deps reported a wired port")
	}
}
