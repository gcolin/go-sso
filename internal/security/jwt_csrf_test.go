package security_test

import (
	"testing"

	"github.com/gcolin/go-sso/internal/security"
	"github.com/gcolin/go-sso/internal/testsupport"
)

func TestCsrfTokenBoundToUser(t *testing.T) {
	cfg := testsupport.NewConfig(t, "http://localhost:8080/sso")
	jwt, err := security.NewJwtService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.CreateCsrfToken("user-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := jwt.ValidateCsrfToken(tok, "user-1"); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if err := jwt.ValidateCsrfToken(tok, "admin-1"); err == nil {
		t.Fatal("expected subject mismatch")
	}
	if err := jwt.ValidateCsrfToken("not-a-jwt", "user-1"); err == nil {
		t.Fatal("expected invalid token")
	}
	anon, err := jwt.CreateCsrfToken("")
	if err != nil {
		t.Fatal(err)
	}
	if err := jwt.ValidateCsrfToken(anon, ""); err != nil {
		t.Fatalf("anon: %v", err)
	}
	if err := jwt.ValidateCsrfToken(anon, "user-1"); err == nil {
		t.Fatal("anon token must not validate for a user")
	}
}
