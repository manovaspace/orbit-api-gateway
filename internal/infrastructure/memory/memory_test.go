package memory

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

func TestChallengesConfirmRemovesOnlyOnAccept(t *testing.T) {
	store := NewChallenges()
	ctx := context.Background()
	challenge := domain.Challenge{Code: "123456", ExpiresAt: time.Now().Add(time.Minute)}
	store.Save(ctx, "owner@example.com", challenge)

	reject := func(domain.Challenge) bool { return false }
	if _, ok := store.Confirm(ctx, "owner@example.com", reject); ok {
		t.Fatal("a rejected challenge was reported as confirmed")
	}
	if _, ok := store.Confirm(ctx, "owner@example.com", reject); ok {
		t.Fatal("a rejected challenge was removed")
	}

	accept := func(candidate domain.Challenge) bool { return candidate.Code == "123456" }
	got, ok := store.Confirm(ctx, "owner@example.com", accept)
	if !ok || got.Code != "123456" {
		t.Fatalf("Confirm = %+v, %v", got, ok)
	}
	if _, ok := store.Confirm(ctx, "owner@example.com", accept); ok {
		t.Fatal("a confirmed challenge stayed stored")
	}
	if _, ok := store.Confirm(ctx, "nobody@example.com", accept); ok {
		t.Fatal("an unknown email was confirmed")
	}
}

func TestChangesSaveReplaces(t *testing.T) {
	store := NewChallenges()
	ctx := context.Background()
	store.Save(ctx, "owner@example.com", domain.Challenge{Code: "111111"})
	store.Save(ctx, "owner@example.com", domain.Challenge{Code: "222222"})

	got, ok := store.Confirm(ctx, "owner@example.com", func(domain.Challenge) bool { return true })
	if !ok || got.Code != "222222" {
		t.Fatalf("Confirm = %+v, %v", got, ok)
	}
}

func TestClaimsRoundTrip(t *testing.T) {
	store := NewClaims()
	ctx := context.Background()
	if _, ok := store.Get(ctx, "idem-1"); ok {
		t.Fatal("an empty cache returned a claim")
	}
	result := domain.ClaimResult{Status: domain.ClaimStatusProvisioned, User: domain.ClaimUser{UID: "john"}}
	store.Put(ctx, "idem-1", result)
	got, ok := store.Get(ctx, "idem-1")
	if !ok || got.User.UID != "john" {
		t.Fatalf("Get = %+v, %v", got, ok)
	}
}

// TestStoresAreSafeForConcurrentUse is meaningful under -race: the routes are
// served concurrently.
func TestStoresAreSafeForConcurrentUse(t *testing.T) {
	challenges := NewChallenges()
	claims := NewClaims()
	ctx := context.Background()

	var group sync.WaitGroup
	for i := 0; i < 50; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			challenges.Save(ctx, "owner@example.com", domain.Challenge{Code: "123456"})
			_, _ = challenges.Confirm(ctx, "owner@example.com", func(domain.Challenge) bool { return true })
			claims.Put(ctx, "idem", domain.ClaimResult{Status: domain.ClaimStatusProvisioned})
			_, _ = claims.Get(ctx, "idem")
		}()
	}
	group.Wait()
}
