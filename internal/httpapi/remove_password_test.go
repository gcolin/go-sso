package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/httpapi"
	"github.com/gcolin/go-sso/internal/runtime"
	"github.com/gcolin/go-sso/internal/security"
	"github.com/gcolin/go-sso/internal/testsupport"
)

func TestRemovePasswordRequiresFederationLink(t *testing.T) {
	h := testsupport.NewHandler(t, ssoBase)
	cookie := testsupport.LoginCookie(t, h, "/sso", testsupport.UserEmail, testsupport.Password)

	rec := get(t, h, "/sso/profile/password", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "removeNeedsFederation") &&
		!strings.Contains(rec.Body.String(), "fournisseur") &&
		!strings.Contains(rec.Body.String(), "provider") {
		// French hint about federation
		if !strings.Contains(rec.Body.String(), "externe") && !strings.Contains(rec.Body.String(), "Google") {
			t.Fatalf("expected federation hint, got %s", truncate(rec.Body.String(), 400))
		}
	}
	if strings.Contains(rec.Body.String(), `action="/sso/profile/password/remove"`) {
		t.Fatal("remove form should be hidden without linked IdP")
	}
}

func TestRemovePasswordClearsPasswordAndTotp(t *testing.T) {
	cfg := testsupport.NewConfig(t, ssoBase)
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
	idx := -1
	for i := range rt.Config.Users {
		if rt.Config.Users[i].ID == user.ID {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("user index")
	}
	rt.Config.Users[idx].AuthProvider = "google"
	rt.Config.Users[idx].ExternalSubject = "google-sub-1"
	if err := loader.Save(rt.Config); err != nil {
		t.Fatal(err)
	}
	rt.Users.Reload()
	secret, err := rt.UserReg.BeginTotpSetup(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.UserReg.ConfirmTotpSetup(user.ID, security.CurrentTotpCode(secret)); err != nil {
		t.Fatal(err)
	}

	h := httpapi.New(rt).Handler()
	// Login via API then 2FA
	loginBody := `{"email":"` + testsupport.UserEmail + `","password":"` + testsupport.Password + `"}`
	loginReq := httptest.NewRequest(http.MethodPost, "/sso/api/auth/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	h.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK || !strings.Contains(loginRec.Body.String(), "2fa_required") {
		t.Fatalf("login status=%d body=%s", loginRec.Code, loginRec.Body.String())
	}
	var pending string
	if i := strings.Index(loginRec.Body.String(), `"pendingToken":"`); i >= 0 {
		rest := loginRec.Body.String()[i+len(`"pendingToken":"`):]
		pending, _, _ = strings.Cut(rest, `"`)
	}
	verifyBody := `{"pendingToken":"` + pending + `","code":"` + security.CurrentTotpCode(secret) + `"}`
	verifyReq := httptest.NewRequest(http.MethodPost, "/sso/api/auth/2fa/verify", strings.NewReader(verifyBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyRec := httptest.NewRecorder()
	h.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("2fa status=%d body=%s", verifyRec.Code, verifyRec.Body.String())
	}
	cookie := ""
	for _, c := range verifyRec.Result().Cookies() {
		if c.Name == "datanode_sso_session" {
			cookie = c.Name + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatal("missing session")
	}

	form := url.Values{
		"_csrf": {testsupport.CSRFToken(t, rt, user.ID)},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/profile/password/remove", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	updated, ok := rt.UserReg.FindByID(user.ID)
	if !ok {
		t.Fatal("user gone")
	}
	if updated.HasLocalPassword() {
		t.Fatal("password should be cleared")
	}
	if updated.IsTotpEnabled() {
		t.Fatal("totp should be cleared")
	}
	if updated.AuthProvider != "google" || updated.ExternalSubject != "google-sub-1" {
		t.Fatal("federation link should remain")
	}
}
