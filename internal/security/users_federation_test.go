package security_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/model"
	"github.com/gcolin/go-sso/internal/runtime"
	"github.com/gcolin/go-sso/internal/security"
	"github.com/gcolin/go-sso/internal/testsupport"
)

func TestResolveExternalLoginClearsPasswordWhenUnverified(t *testing.T) {
	cfg := testsupport.NewConfig(t, "http://localhost:8080/sso")
	cfg.Mail.Enabled = true
	cfg.Mail.FromAddress = "noreply@example.com"
	path := filepath.Join(t.TempDir(), "sso-server.json")
	loader := config.NewLoader(path)
	if err := loader.Save(cfg); err != nil {
		t.Fatal(err)
	}
	rt, err := runtime.New(cfg, loader)
	if err != nil {
		t.Fatal(err)
	}

	email := "bob@corp.com"
	user, err := rt.UserReg.Create(email, "Bob", model.TypeUser, testsupport.Password, 0)
	if err != nil {
		t.Fatal(err)
	}
	if user.IsEmailVerified() {
		t.Fatal("expected unverified local user when mail enabled")
	}
	if !user.HasLocalPassword() {
		t.Fatal("expected local password")
	}
	secret, err := rt.UserReg.BeginTotpSetup(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.UserReg.ConfirmTotpSetup(user.ID, security.CurrentTotpCode(secret)); err != nil {
		t.Fatal(err)
	}

	// Anonymous link allowed for unverified (wipes credentials).
	linked, err := rt.UserReg.ResolveExternalLogin("google", "google-sub-bob", email, "Bob Google", "")
	if err != nil {
		t.Fatal(err)
	}
	if linked.AuthProvider != "google" || linked.ExternalSubject != "google-sub-bob" {
		t.Fatalf("federation fields: provider=%q sub=%q", linked.AuthProvider, linked.ExternalSubject)
	}
	if !linked.IsEmailVerified() {
		t.Fatal("expected verified after IdP link")
	}
	if linked.HasLocalPassword() {
		t.Fatal("local password must be cleared for unverified squat account")
	}
	if linked.IsTotpEnabled() {
		t.Fatal("totp must be cleared for unverified squat account")
	}
}

func TestResolveExternalLoginRequiresSessionForVerifiedPassword(t *testing.T) {
	cfg := testsupport.NewConfig(t, "http://localhost:8080/sso")
	path := filepath.Join(t.TempDir(), "sso-server.json")
	loader := config.NewLoader(path)
	if err := loader.Save(cfg); err != nil {
		t.Fatal(err)
	}
	rt, err := runtime.New(cfg, loader)
	if err != nil {
		t.Fatal(err)
	}

	before, ok := rt.UserReg.FindByEmail(testsupport.UserEmail)
	if !ok || !before.IsEmailVerified() || !before.HasLocalPassword() {
		t.Fatal("expected verified fixture user with password")
	}

	_, err = rt.UserReg.ResolveExternalLogin("google", "google-sub-user1", testsupport.UserEmail, "Demo", "")
	if err == nil {
		t.Fatal("anonymous link must be refused for verified+password account")
	}
	var denied *security.ExternalLoginNotAllowedError
	if !errors.As(err, &denied) || denied.MessageKey != "error.external.login_required_to_link" {
		t.Fatalf("err=%v", err)
	}

	linked, err := rt.UserReg.ResolveExternalLogin("google", "google-sub-user1", testsupport.UserEmail, "Demo", before.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !linked.HasLocalPassword() {
		t.Fatal("verified account should keep local password on explicit link")
	}
	if linked.AuthProvider != "google" {
		t.Fatalf("AuthProvider=%q", linked.AuthProvider)
	}
}

func TestResolveExternalLoginRefusesIdPOverwrite(t *testing.T) {
	cfg := testsupport.NewConfig(t, "http://localhost:8080/sso")
	path := filepath.Join(t.TempDir(), "sso-server.json")
	loader := config.NewLoader(path)
	if err := loader.Save(cfg); err != nil {
		t.Fatal(err)
	}
	rt, err := runtime.New(cfg, loader)
	if err != nil {
		t.Fatal(err)
	}

	user, ok := rt.UserReg.FindByEmail(testsupport.UserEmail)
	if !ok {
		t.Fatal("missing fixture user")
	}
	if _, err := rt.UserReg.ResolveExternalLogin("google", "google-sub-user1", testsupport.UserEmail, "Demo", user.ID); err != nil {
		t.Fatal(err)
	}

	_, err = rt.UserReg.ResolveExternalLogin("microsoft", "ms-sub-attacker", testsupport.UserEmail, "Attacker", "")
	if err == nil {
		t.Fatal("expected refusal when overwriting IdP")
	}
	var denied *security.ExternalLoginNotAllowedError
	if !errors.As(err, &denied) {
		t.Fatalf("err type=%T %v", err, err)
	}
	if denied.MessageKey != "error.external.already_linked" {
		t.Fatalf("MessageKey=%q", denied.MessageKey)
	}
	if len(denied.MessageArgs) != 1 || denied.MessageArgs[0] != "google" {
		t.Fatalf("MessageArgs=%v", denied.MessageArgs)
	}

	still, ok := rt.UserReg.FindByEmail(testsupport.UserEmail)
	if !ok || still.AuthProvider != "google" || still.ExternalSubject != "google-sub-user1" {
		t.Fatalf("IdP binding mutated: provider=%q sub=%q", still.AuthProvider, still.ExternalSubject)
	}

	same, err := rt.UserReg.ResolveExternalLogin("google", "google-sub-user1", testsupport.UserEmail, "Demo", "")
	if err != nil {
		t.Fatal(err)
	}
	if same.AuthProvider != "google" {
		t.Fatalf("AuthProvider=%q", same.AuthProvider)
	}
}
