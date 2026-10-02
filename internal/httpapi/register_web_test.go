package httpapi_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/httpapi"
	"github.com/gcolin/go-sso/internal/mail"
	"github.com/gcolin/go-sso/internal/runtime"
	"github.com/gcolin/go-sso/internal/testsupport"
)

func TestRegisterFormRendersWhenEnabled(t *testing.T) {
	_, h := registerFixture(t, true, true)
	rec := get(t, h, "/sso/register?returnUrl=%2Foauth%2Freturn", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `action="/sso/register"`) && !strings.Contains(body, `name="email"`) {
		t.Fatalf("expected register form, got %s", truncate(body, 300))
	}
}

func TestRegisterFormBlockedWhenDisabled(t *testing.T) {
	_, h := registerFixture(t, false, true)
	rec := get(t, h, "/sso/register", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "désactivée") && !strings.Contains(strings.ToLower(body), "disabled") {
		t.Fatalf("expected disabled error page, got %s", truncate(body, 300))
	}
}

func TestRegisterFormBlockedWhenMailDisabled(t *testing.T) {
	_, h := registerFixture(t, true, false)
	rec := get(t, h, "/sso/register", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "e-mails") && !strings.Contains(strings.ToLower(body), "mail") &&
		!strings.Contains(body, "désactivée") && !strings.Contains(strings.ToLower(body), "disabled") {
		t.Fatalf("expected mail-required or disabled page, got %s", truncate(body, 400))
	}
	login := get(t, h, "/sso/login", "")
	if strings.Contains(login.Body.String(), "/register") && strings.Contains(login.Body.String(), "Créer") {
		// French create-account link should be hidden
		if strings.Contains(login.Body.String(), `href="/sso/register"`) || strings.Contains(login.Body.String(), `href="/register"`) {
			t.Fatal("register link must not appear on login when mail is off")
		}
	}
}

func TestRegisterSubmitCreatesUserWhenEnabled(t *testing.T) {
	rt, h := registerFixture(t, true, true)
	email := fmt.Sprintf("register-%d@example.com", time.Now().UnixNano())
	form := url.Values{
		"email":           {email},
		"name":            {"New User"},
		"password":        {testsupport.Password},
		"confirmPassword": {testsupport.Password},
		"returnUrl":       {"/"},
		"_csrf":           {testsupport.CSRFToken(t, rt, "")},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rec.Code, truncate(rec.Body.String(), 300))
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/register/pending") {
		t.Fatalf("location=%q want pending (mail verification)", loc)
	}
}

func TestRegisterSubmitRejectsPasswordMismatch(t *testing.T) {
	rt, h := registerFixture(t, true, true)
	form := url.Values{
		"email":           {fmt.Sprintf("mismatch-%d@example.com", time.Now().UnixNano())},
		"name":            {"Name"},
		"password":        {testsupport.Password},
		"confirmPassword": {"OtherPassword123"},
		"returnUrl":       {"/"},
		"_csrf":           {testsupport.CSRFToken(t, rt, "")},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "name=\"email\"") {
		t.Fatalf("expected register form again, got %s", truncate(body, 300))
	}
}

func TestRegisterSubmitBlockedWhenDisabled(t *testing.T) {
	_, h := registerFixture(t, false, true)
	form := url.Values{
		"email":           {fmt.Sprintf("disabled-%d@example.com", time.Now().UnixNano())},
		"name":            {"Name"},
		"password":        {testsupport.Password},
		"confirmPassword": {testsupport.Password},
		"returnUrl":       {"/"},
		"_csrf":           {"test"},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "désactivée") && !strings.Contains(strings.ToLower(body), "disabled") {
		t.Fatalf("expected disabled error page, got %s", truncate(body, 300))
	}
}

func TestRegisterSubmitBlockedWhenMailDisabled(t *testing.T) {
	rt, h := registerFixture(t, true, false)
	form := url.Values{
		"email":           {fmt.Sprintf("nomail-%d@example.com", time.Now().UnixNano())},
		"name":            {"Name"},
		"password":        {testsupport.Password},
		"confirmPassword": {testsupport.Password},
		"returnUrl":       {"/"},
		"_csrf":           {testsupport.CSRFToken(t, rt, "")},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if _, ok := rt.UserReg.FindByEmail(form.Get("email")); ok {
		t.Fatal("user must not be created when mail is disabled")
	}
}

func registerFixture(t *testing.T, publicReg, mailEnabled bool) (*runtime.Runtime, http.Handler) {
	t.Helper()
	cfg := testsupport.NewConfig(t, ssoBase)
	cfg.Security.PublicRegistrationEnabled = publicReg
	cfg.Mail.Enabled = mailEnabled
	cfg.Mail.FromAddress = "noreply@example.com"
	path := filepath.Join(t.TempDir(), "sso-server.json")
	loader := config.NewLoader(path)
	if err := loader.Save(cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	rt, err := runtime.New(cfg, loader)
	if err != nil {
		t.Fatalf("runtime: %v", err)
	}
	if mailEnabled {
		rt.AccountVerify = mail.NewAccountVerificationService(cfg, &stubSender{enabled: true}, rt.Templates, rt.JWT, rt.UserReg, rt.Messages)
	}
	return rt, httpapi.New(rt).Handler()
}
