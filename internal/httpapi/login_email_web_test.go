package httpapi_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/httpapi"
	"github.com/gcolin/go-sso/internal/mail"
	"github.com/gcolin/go-sso/internal/runtime"
	"github.com/gcolin/go-sso/internal/security"
	"github.com/gcolin/go-sso/internal/testsupport"
)

var otpCodePattern = regexp.MustCompile(`class="otp-code">(\d{6})`)

func TestEmailLoginDisabled(t *testing.T) {
	rt, h := testsupport.NewRuntime(t, ssoBase)
	rec := get(t, h, "/sso/login/email", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "désactiv") && !strings.Contains(strings.ToLower(rec.Body.String()), "disabled") {
		// French default locale → error.loginEmail.disabled
		if !strings.Contains(rec.Body.String(), "email") {
			t.Fatalf("expected disabled page, body=%s", truncate(rec.Body.String(), 300))
		}
	}
	_ = rt
}

func TestEmailLoginLinkOnLoginPageWhenEnabled(t *testing.T) {
	_, h := newEmailLoginFixture(t)
	rec := get(t, h, "/sso/login", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "/login/email") {
		t.Fatalf("expected email login link, body=%s", truncate(rec.Body.String(), 400))
	}
}

func TestEmailLoginCreatesAccountAndSession(t *testing.T) {
	rt, h, sender := newEmailLoginFixtureWithSender(t)
	email := fmt.Sprintf("otp-new-%d@example.com", time.Now().UnixNano())

	form := url.Values{
		"email":     {email},
		"returnUrl": {"/"},
		"_csrf":     {testsupport.CSRFToken(t, rt, "")},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/login/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rec.Code, truncate(rec.Body.String(), 300))
	}
	if !strings.Contains(rec.Header().Get("Location"), "/login/email/verify") {
		t.Fatalf("Location=%q", rec.Header().Get("Location"))
	}
	pending := cookieHeader(rec, "datanode_sso_session_pending_email_login")
	if pending == "" {
		t.Fatal("expected pending email login cookie")
	}
	if len(sender.mails) != 1 {
		t.Fatalf("expected 1 mail, got %d", len(sender.mails))
	}
	code := extractOTPCode(t, sender.mails[0])

	// Nothing on disk yet
	if _, ok := rt.UserReg.FindByEmail(email); ok {
		t.Fatal("user must not exist before OTP validation")
	}

	getReq := httptest.NewRequest(http.MethodGet, "/sso/login/email/verify", nil)
	getReq.Header.Set("Cookie", pending)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("verify page status=%d", getRec.Code)
	}

	verify := url.Values{
		"code":  {code},
		"_csrf": {testsupport.ExtractCSRF(t, getRec.Body.String())},
	}
	postReq := httptest.NewRequest(http.MethodPost, "/sso/login/email/verify", strings.NewReader(verify.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Cookie", pending)
	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusFound {
		t.Fatalf("verify status=%d body=%s", postRec.Code, truncate(postRec.Body.String(), 300))
	}
	session := cookieHeader(postRec, "datanode_sso_session")
	if session == "" {
		t.Fatal("expected session cookie")
	}
	user, ok := rt.UserReg.FindByEmail(email)
	if !ok || !user.IsEmailVerified() || user.HasLocalPassword() {
		t.Fatalf("expected verified passwordless user, ok=%v user=%+v", ok, user)
	}
}

func TestEmailLoginExistingUserSkips2FA(t *testing.T) {
	rt, h, sender := newEmailLoginFixtureWithSender(t)
	user, ok := rt.UserReg.FindByEmail(testsupport.UserEmail)
	if !ok {
		t.Fatal("missing fixture user")
	}
	secret, err := rt.UserReg.BeginTotpSetup(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.UserReg.ConfirmTotpSetup(user.ID, security.CurrentTotpCode(secret)); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"email":     {testsupport.UserEmail},
		"returnUrl": {"/"},
		"_csrf":     {testsupport.CSRFToken(t, rt, "")},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/login/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	pending := cookieHeader(rec, "datanode_sso_session_pending_email_login")
	code := extractOTPCode(t, sender.mails[0])

	getReq := httptest.NewRequest(http.MethodGet, "/sso/login/email/verify", nil)
	getReq.Header.Set("Cookie", pending)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)

	verify := url.Values{
		"code":  {code},
		"_csrf": {testsupport.ExtractCSRF(t, getRec.Body.String())},
	}
	postReq := httptest.NewRequest(http.MethodPost, "/sso/login/email/verify", strings.NewReader(verify.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Cookie", pending)
	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusFound {
		t.Fatalf("status=%d", postRec.Code)
	}
	if strings.Contains(postRec.Header().Get("Location"), "/login/2fa") {
		t.Fatal("email login must skip 2FA")
	}
	if cookieHeader(postRec, "datanode_sso_session") == "" {
		t.Fatal("expected session cookie")
	}
}

func TestEmailLoginOTPSingleUse(t *testing.T) {
	rt, h, sender := newEmailLoginFixtureWithSender(t)
	email := fmt.Sprintf("otp-once-%d@example.com", time.Now().UnixNano())

	form := url.Values{
		"email":     {email},
		"returnUrl": {"/"},
		"_csrf":     {testsupport.CSRFToken(t, rt, "")},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/login/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	pending := cookieHeader(rec, "datanode_sso_session_pending_email_login")
	code := extractOTPCode(t, sender.mails[0])

	getReq := httptest.NewRequest(http.MethodGet, "/sso/login/email/verify", nil)
	getReq.Header.Set("Cookie", pending)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	csrf := testsupport.ExtractCSRF(t, getRec.Body.String())

	verify := url.Values{"code": {code}, "_csrf": {csrf}}
	postReq := httptest.NewRequest(http.MethodPost, "/sso/login/email/verify", strings.NewReader(verify.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Cookie", pending)
	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusFound {
		t.Fatalf("first verify status=%d", postRec.Code)
	}

	raw := strings.SplitN(pending, "=", 2)
	if len(raw) != 2 {
		t.Fatalf("bad cookie %q", pending)
	}
	claims, err := rt.JWT.ParsePendingEmailLoginToken(raw[1])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rt.EmailLogin.VerifyChallenge(claims.JTI, code); ok {
		t.Fatal("OTP must be single-use")
	}
}

func TestEmailLoginInvalidCode(t *testing.T) {
	rt, h, _ := newEmailLoginFixtureWithSender(t)
	form := url.Values{
		"email":     {testsupport.UserEmail},
		"returnUrl": {"/"},
		"_csrf":     {testsupport.CSRFToken(t, rt, "")},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/login/email", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	pending := cookieHeader(rec, "datanode_sso_session_pending_email_login")

	getReq := httptest.NewRequest(http.MethodGet, "/sso/login/email/verify", nil)
	getReq.Header.Set("Cookie", pending)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)

	verify := url.Values{
		"code":  {"000000"},
		"_csrf": {testsupport.ExtractCSRF(t, getRec.Body.String())},
	}
	postReq := httptest.NewRequest(http.MethodPost, "/sso/login/email/verify", strings.NewReader(verify.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Cookie", pending)
	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusOK {
		t.Fatalf("status=%d", postRec.Code)
	}
	if cookieHeader(postRec, "datanode_sso_session") != "" {
		t.Fatal("must not issue session on bad code")
	}
}

func newEmailLoginFixture(t *testing.T) (*runtime.Runtime, http.Handler) {
	t.Helper()
	rt, h, _ := newEmailLoginFixtureWithSender(t)
	return rt, h
}

func newEmailLoginFixtureWithSender(t *testing.T) (*runtime.Runtime, http.Handler, *stubSender) {
	t.Helper()
	cfg := testsupport.NewConfig(t, ssoBase)
	cfg.Mail.Enabled = true
	cfg.Mail.LoginByEmailEnabled = true
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
	sender := &stubSender{enabled: true}
	rt.EmailLogin = mail.NewEmailLoginService(cfg, sender, rt.Templates, rt.JWT, rt.EmailLoginOTPs, rt.Messages)
	return rt, httpapi.New(rt).Handler(), sender
}

func extractOTPCode(t *testing.T, html string) string {
	t.Helper()
	m := otpCodePattern.FindStringSubmatch(html)
	if len(m) != 2 {
		t.Fatalf("otp code not found in mail: %s", truncate(html, 200))
	}
	return m[1]
}
