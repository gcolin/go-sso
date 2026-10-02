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

func TestHTMLLoginRedirectsTo2FAWhenTotpEnabled(t *testing.T) {
	rt, h := newTotpEnabledFixture(t)

	form := url.Values{
		"email":     {testsupport.UserEmail},
		"password":  {testsupport.Password},
		"returnUrl": {"/oauth/authorize?client_id=test-client"},
		"_csrf":     {testsupport.CSRFToken(t, rt, "")},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/login/2fa") {
		t.Fatalf("Location=%q", loc)
	}
	pending := cookieHeader(rec, "datanode_sso_session_pending_2fa")
	if pending == "" {
		t.Fatal("expected pending 2FA cookie")
	}
}

func TestHTMLLogin2FACompletesSession(t *testing.T) {
	rt, h := newTotpEnabledFixture(t)
	user, ok := rt.UserReg.FindByEmail(testsupport.UserEmail)
	if !ok {
		t.Fatal("missing user")
	}
	secret := user.TotpSecret

	form := url.Values{
		"email":     {testsupport.UserEmail},
		"password":  {testsupport.Password},
		"returnUrl": {"/"},
		"_csrf":     {testsupport.CSRFToken(t, rt, "")},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	pending := cookieHeader(rec, "datanode_sso_session_pending_2fa")
	if pending == "" {
		t.Fatal("expected pending 2FA cookie")
	}

	getReq := httptest.NewRequest(http.MethodGet, "/sso/login/2fa", nil)
	getReq.Header.Set("Cookie", pending)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("2fa page status=%d", getRec.Code)
	}
	if !strings.Contains(getRec.Body.String(), `name="code"`) {
		t.Fatal("expected code field on 2fa page")
	}

	verify := url.Values{
		"code":  {security.CurrentTotpCode(secret)},
		"_csrf": {testsupport.ExtractCSRF(t, getRec.Body.String())},
	}
	postReq := httptest.NewRequest(http.MethodPost, "/sso/login/2fa", strings.NewReader(verify.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Cookie", pending)
	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusFound {
		t.Fatalf("verify status=%d body=%s", postRec.Code, postRec.Body.String())
	}
	session := cookieHeader(postRec, "datanode_sso_session")
	if session == "" || strings.Contains(session, "Max-Age=0") {
		t.Fatalf("expected session cookie, got %q", session)
	}
}

func newTotpEnabledFixture(t *testing.T) (*runtime.Runtime, http.Handler) {
	t.Helper()
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
	secret, err := rt.UserReg.BeginTotpSetup(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.UserReg.ConfirmTotpSetup(user.ID, security.CurrentTotpCode(secret)); err != nil {
		t.Fatal(err)
	}
	return rt, httpapi.New(rt).Handler()
}

func cookieHeader(rec *httptest.ResponseRecorder, name string) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.Value != "" && c.MaxAge != -1 {
			return c.Name + "=" + c.Value
		}
	}
	return ""
}
