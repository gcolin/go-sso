package security_test

import (
	"path/filepath"
	"testing"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/runtime"
	"github.com/gcolin/go-sso/internal/security"
	"github.com/gcolin/go-sso/internal/testsupport"
)

func TestDisableTotpWithCredentialsRequiresStepUp(t *testing.T) {
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
		t.Fatal("missing user")
	}
	secret, err := rt.UserReg.BeginTotpSetup(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.UserReg.ConfirmTotpSetup(user.ID, security.CurrentTotpCode(secret)); err != nil {
		t.Fatal(err)
	}

	if err := rt.UserReg.DisableTotpWithCredentials(user.ID, "", ""); err == nil {
		t.Fatal("expected failure without credentials")
	}
	if err := rt.UserReg.DisableTotpWithCredentials(user.ID, "wrong-password", security.CurrentTotpCode(secret)); err == nil {
		t.Fatal("expected failure with wrong password")
	}
	if err := rt.UserReg.DisableTotpWithCredentials(user.ID, testsupport.Password, "000000"); err == nil {
		t.Fatal("expected failure with wrong totp")
	}
	if err := rt.UserReg.DisableTotpWithCredentials(user.ID, testsupport.Password, security.CurrentTotpCode(secret)); err != nil {
		t.Fatal(err)
	}
	updated, ok := rt.UserReg.FindByID(user.ID)
	if !ok || updated.IsTotpEnabled() {
		t.Fatal("totp should be disabled")
	}
}

func TestDisableTotpWithCredentialsFederatedOnlyUsesTotp(t *testing.T) {
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
		t.Fatal("missing user")
	}
	secret, err := rt.UserReg.BeginTotpSetup(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.UserReg.ConfirmTotpSetup(user.ID, security.CurrentTotpCode(secret)); err != nil {
		t.Fatal(err)
	}
	// Simulate federated-only: clear password, keep IdP + TOTP.
	idx := -1
	for i := range rt.Config.Users {
		if rt.Config.Users[i].ID == user.ID {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("user missing in config")
	}
	rt.Config.Users[idx].PasswordHash = ""
	rt.Config.Users[idx].AuthProvider = "google"
	rt.Config.Users[idx].ExternalSubject = "google-sub"
	if err := loader.Save(rt.Config); err != nil {
		t.Fatal(err)
	}
	rt.Users.Reload()

	fed, ok := rt.UserReg.FindByID(user.ID)
	if !ok || fed.HasLocalPassword() || !fed.IsTotpEnabled() {
		t.Fatal("expected federated-only user with totp")
	}
	if err := rt.UserReg.DisableTotpWithCredentials(user.ID, "", security.CurrentTotpCode(secret)); err != nil {
		t.Fatal(err)
	}
	updated, ok := rt.UserReg.FindByID(user.ID)
	if !ok || updated.IsTotpEnabled() {
		t.Fatal("totp should be disabled")
	}
}
