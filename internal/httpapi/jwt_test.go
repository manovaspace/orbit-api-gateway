package httpapi

import (
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTAuth_ValidToken(t *testing.T) {
	secret := []byte("test-secret")
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user-1",
	}).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("JWT_SECRET", "test-secret")
	called := false
	h := JWTAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if UserIDFromContext(r.Context()) != "user-1" {
			t.Fatalf("user id missing")
		}
	}))
	req := httptestReq("GET", "/", token)
	rec := httptestRec()
	h.ServeHTTP(rec, req)
	if !called || rec.Code != 200 {
		t.Fatalf("code=%d called=%v", rec.Code, called)
	}
}
