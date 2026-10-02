package security

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("admin123")
	if err != nil {
		t.Fatal(err)
	}
	if !IsValidPasswordFormat(hash) {
		t.Fatalf("invalid format: %s", hash)
	}
	if !VerifyPassword("admin123", hash) {
		t.Fatal("verify failed for correct password")
	}
	if VerifyPassword("wrong", hash) {
		t.Fatal("verify succeeded for wrong password")
	}
	if !stringsHasPrefix(hash, "pbkdf2-sha256$210000$") {
		t.Fatalf("unexpected prefix: %s", hash)
	}
}

func TestVerifyPasswordAcceptsKeycloakJavaUTF16BE(t *testing.T) {
	// Keycloak / Java JCE encode the password as UTF-16BE before PBKDF2.
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	iterations := 27500
	dk := pbkdf2.Key(passwordUTF16BE("keycloak-secret"), salt, iterations, 32, sha256.New)
	hash := fmt.Sprintf("pbkdf2-sha256$%d$%s$%s",
		iterations,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(dk),
	)
	if !VerifyPassword("keycloak-secret", hash) {
		t.Fatal("expected Keycloak/Java-style hash to verify")
	}
	if VerifyPassword("wrong", hash) {
		t.Fatal("wrong password must not verify")
	}
}

func stringsHasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}
