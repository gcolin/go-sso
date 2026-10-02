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
	"github.com/gcolin/go-sso/internal/model"
	"github.com/gcolin/go-sso/internal/runtime"
	"github.com/gcolin/go-sso/internal/security"
	"github.com/gcolin/go-sso/internal/testsupport"
)

func TestVerifyEmailActivatesAccount(t *testing.T) {
	cfg := testsupport.NewConfig(t, ssoBase)
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
	email := fmt.Sprintf("verify-%d@example.com", time.Now().UnixNano())
	user, err := rt.UserReg.Create(email, "Verify Me", model.TypeUser, testsupport.Password, 0)
	if err != nil {
		t.Fatal(err)
	}
	if user.IsEmailVerified() {
		t.Fatal("expected unverified user when mail enabled")
	}
	token, err := rt.JWT.CreateEmailVerificationToken(user.ID, user.Email)
	if err != nil {
		t.Fatal(err)
	}
	h := httpapi.New(rt).Handler()
	rec := get(t, h, "/sso/verify-email?token="+url.QueryEscape(token), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, truncate(rec.Body.String(), 300))
	}
	if !strings.Contains(rec.Body.String(), email) && !strings.Contains(rec.Body.String(), "valid") {
		// French success page should mention validation
		if !strings.Contains(rec.Body.String(), "valid") && !strings.Contains(rec.Body.String(), "Compte") {
			t.Fatalf("unexpected body %s", truncate(rec.Body.String(), 300))
		}
	}
	updated, ok := rt.UserReg.FindByID(user.ID)
	if !ok || !updated.IsEmailVerified() {
		t.Fatal("user should be verified after clicking link")
	}
}

func TestRegisterWithMailSendsVerification(t *testing.T) {
	cfg := testsupport.NewConfig(t, ssoBase)
	cfg.Mail.Enabled = true
	cfg.Mail.FromAddress = "noreply@example.com"
	cfg.Security.PublicRegistrationEnabled = true
	path := filepath.Join(t.TempDir(), "sso-server.json")
	loader := config.NewLoader(path)
	if err := loader.Save(cfg); err != nil {
		t.Fatal(err)
	}
	rt, err := runtime.New(cfg, loader)
	if err != nil {
		t.Fatal(err)
	}
	sender := &stubSender{enabled: true}
	rt.AccountVerify = mail.NewAccountVerificationService(cfg, sender, rt.Templates, rt.JWT, rt.UserReg, rt.Messages)
	h := httpapi.New(rt).Handler()

	email := fmt.Sprintf("regmail-%d@example.com", time.Now().UnixNano())
	form := url.Values{
		"email":           {email},
		"name":            {"Reg User"},
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
	if !strings.Contains(loc, "/register/pending") || !strings.Contains(loc, "email=") {
		t.Fatalf("location=%q", loc)
	}
	if !strings.Contains(loc, "returnUrl=") {
		t.Fatalf("expected returnUrl in location=%q", loc)
	}
	if len(sender.mails) != 1 {
		t.Fatalf("expected 1 mail, got %d", len(sender.mails))
	}
	user, ok := rt.UserReg.FindByEmail(email)
	if !ok || user.IsEmailVerified() {
		t.Fatal("registered user should be unverified")
	}
	if rt.Passwords.Authenticate(email, testsupport.Password) != nil {
		t.Fatal("unverified user must not authenticate")
	}
	if status := rt.Passwords.AuthenticateStatus(email, testsupport.Password); status != security.AuthEmailNotVerified {
		t.Fatalf("status=%v", status)
	}

	// Pending page keeps returnUrl and rejects until verified.
	pending := get(t, h, loc, "")
	if pending.Code != http.StatusOK {
		t.Fatalf("pending status=%d", pending.Code)
	}
	if !strings.Contains(pending.Body.String(), "validé mon compte") && !strings.Contains(pending.Body.String(), "I have verified") {
		t.Fatalf("expected confirmed button, got %s", truncate(pending.Body.String(), 800))
	}
	check := url.Values{
		"email":     {email},
		"returnUrl": {"/oauth/authorize?x=1"},
		"_csrf":     {testsupport.CSRFToken(t, rt, "")},
	}
	req2 := httptest.NewRequest(http.MethodPost, "/sso/register/pending", strings.NewReader(check.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected pending again, status=%d", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), "pas encore validé") && !strings.Contains(rec2.Body.String(), "not verified") {
		t.Fatalf("expected not-verified message, got %s", truncate(rec2.Body.String(), 400))
	}

	// After email verification + pending cookie → auto login to returnUrl.
	if err := rt.UserReg.MarkEmailVerified(user.ID); err != nil {
		t.Fatal(err)
	}
	cookie := ""
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "pending_registration") {
			cookie = c.Name + "=" + c.Value
			break
		}
	}
	if cookie == "" {
		t.Fatal("expected pending_registration cookie after register")
	}
	check["returnUrl"] = []string{"/oauth/authorize?x=1"}
	check["_csrf"] = []string{testsupport.CSRFToken(t, rt, user.ID)}
	req3 := httptest.NewRequest(http.MethodPost, "/sso/register/pending", strings.NewReader(check.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req3.Header.Set("Cookie", cookie)
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusFound {
		t.Fatalf("auto-login status=%d body=%s", rec3.Code, truncate(rec3.Body.String(), 300))
	}
	loc3 := rec3.Header().Get("Location")
	if !strings.Contains(loc3, "/oauth/authorize") {
		t.Fatalf("expected returnUrl redirect, got %q", loc3)
	}
	sessionSet := false
	for _, c := range rec3.Result().Cookies() {
		if c.Name == "datanode_sso_session" && c.Value != "" && c.MaxAge != -1 {
			sessionSet = true
		}
	}
	if !sessionSet {
		t.Fatal("expected session cookie after auto-login")
	}
}

func TestResendDoesNotMintPendingRegistrationCookie(t *testing.T) {
	cfg := testsupport.NewConfig(t, ssoBase)
	cfg.Mail.Enabled = true
	cfg.Mail.FromAddress = "noreply@example.com"
	cfg.Security.PublicRegistrationEnabled = true
	path := filepath.Join(t.TempDir(), "sso-server.json")
	loader := config.NewLoader(path)
	if err := loader.Save(cfg); err != nil {
		t.Fatal(err)
	}
	rt, err := runtime.New(cfg, loader)
	if err != nil {
		t.Fatal(err)
	}
	sender := &stubSender{enabled: true}
	rt.AccountVerify = mail.NewAccountVerificationService(cfg, sender, rt.Templates, rt.JWT, rt.UserReg, rt.Messages)
	h := httpapi.New(rt).Handler()

	email := fmt.Sprintf("resend-steal-%d@example.com", time.Now().UnixNano())
	user, err := rt.UserReg.Create(email, "Target", model.TypeUser, testsupport.Password, 0)
	if err != nil {
		t.Fatal(err)
	}
	if user.IsEmailVerified() {
		t.Fatal("expected unverified")
	}

	// Attacker: resend without a prior register cookie must not get pending_registration.
	form := url.Values{
		"email":     {email},
		"returnUrl": {"/"},
		"pending":   {"1"},
		"_csrf":     {testsupport.CSRFToken(t, rt, "")},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/verify-email/resend", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("resend status=%d", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "pending_registration") && c.Value != "" && c.MaxAge != -1 {
			t.Fatalf("resend must not mint pending_registration cookie, got %s", c.Name)
		}
	}
	if len(sender.mails) != 1 {
		t.Fatalf("expected resend mail, got %d", len(sender.mails))
	}

	// After victim verifies, attacker without cookie must not auto-login.
	if err := rt.UserReg.MarkEmailVerified(user.ID); err != nil {
		t.Fatal(err)
	}
	check := url.Values{
		"email":     {email},
		"returnUrl": {"/"},
		"_csrf":     {testsupport.CSRFToken(t, rt, "")},
	}
	req2 := httptest.NewRequest(http.MethodPost, "/sso/register/pending", strings.NewReader(check.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusFound {
		t.Fatalf("pending status=%d want redirect without session", rec2.Code)
	}
	for _, c := range rec2.Result().Cookies() {
		if c.Name == "datanode_sso_session" && c.Value != "" && c.MaxAge != -1 {
			t.Fatal("attacker must not receive session cookie")
		}
	}
}

type stubSender struct {
	enabled bool
	mails   []string
}

func (s *stubSender) IsEnabled() bool { return s.enabled }
func (s *stubSender) SendHTML(to, subject, body string) error {
	s.mails = append(s.mails, body)
	return nil
}
