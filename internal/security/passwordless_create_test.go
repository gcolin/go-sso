package security_test

import (
	"path/filepath"
	"testing"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/runtime"
	"github.com/gcolin/go-sso/internal/testsupport"
)

func TestCreateVerifiedPasswordless(t *testing.T) {
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
	u, err := rt.UserReg.CreateVerifiedPasswordless("pwless@example.com")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u == nil {
		t.Fatal("nil user")
	}
	if !u.IsEmailVerified() || u.HasLocalPassword() {
		t.Fatalf("unexpected user %+v", u)
	}
	again, ok := rt.UserReg.FindByEmail("pwless@example.com")
	if !ok || again.ID != u.ID {
		t.Fatal("not findable after create")
	}
}
