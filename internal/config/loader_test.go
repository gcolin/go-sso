package config

import "testing"

func TestValidateRequiresPublicBaseURL(t *testing.T) {
	cfg, err := BuildDefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("default config should validate: %v", err)
	}
	cfg.Server.PublicBaseURL = ""
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error for empty publicBaseUrl")
	}
}

func TestValidateRequiresUsers(t *testing.T) {
	cfg, err := BuildDefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Users = nil
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error for empty users")
	}
}

func TestValidateRejectsBadPasswordHash(t *testing.T) {
	cfg, err := BuildDefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Users[0].PasswordHash = "not-a-hash"
	if err := Validate(cfg); err == nil {
		t.Fatal("expected error for invalid password hash")
	}
}

func TestHashPasswordFormat(t *testing.T) {
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatal(err)
	}
	if !isValidPasswordHashFormat(hash) {
		t.Fatalf("unexpected hash: %s", hash)
	}
}
