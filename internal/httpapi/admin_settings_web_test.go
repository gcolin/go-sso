package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gcolin/go-sso/internal/testsupport"
)

func TestAdminSettingsServerRendersAndSaves(t *testing.T) {
	rt, h := testsupport.NewRuntime(t, ssoBase)
	cookie := testsupport.LoginCookie(t, h, "/sso", testsupport.AdminEmail, testsupport.Password)

	rec := get(t, h, "/sso/admin/settings/server", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `name="publicBaseUrl"`) {
		t.Fatalf("expected server form, got %s", truncate(body, 400))
	}

	form := url.Values{
		"host":          {"127.0.0.1"},
		"port":          {"8080"},
		"publicBaseUrl": {ssoBase},
		"title":         {"Settings Test SSO"},
		"realm":         {""},
		"defaultLocale": {"fr"},
		"_csrf":         {testsupport.CSRFToken(t, rt, "admin-1")},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/admin/settings/server", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookie)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusFound {
		t.Fatalf("save status=%d body=%s", rec2.Code, truncate(rec2.Body.String(), 300))
	}
	loc := rec2.Header().Get("Location")
	if !strings.Contains(loc, "messageKey=flash.settings.saved") {
		t.Fatalf("location=%q", loc)
	}

	rec3 := get(t, h, "/sso/admin/settings/mail", cookie)
	if rec3.Code != http.StatusOK || !strings.Contains(rec3.Body.String(), `name="smtpHost"`) {
		t.Fatalf("mail page status=%d", rec3.Code)
	}
	rec4 := get(t, h, "/sso/admin/settings/federation", cookie)
	if rec4.Code != http.StatusOK || !strings.Contains(rec4.Body.String(), `name="autoProvision"`) {
		t.Fatalf("federation page status=%d", rec4.Code)
	}
	rec5 := get(t, h, "/sso/admin/settings/security", cookie)
	if rec5.Code != http.StatusOK || !strings.Contains(rec5.Body.String(), `name="publicRegistrationEnabled"`) {
		t.Fatalf("security page status=%d", rec5.Code)
	}
}

func TestAdminSettingsFederationProviderEdit(t *testing.T) {
	rt, h := testsupport.NewRuntime(t, ssoBase)
	cookie := testsupport.LoginCookie(t, h, "/sso", testsupport.AdminEmail, testsupport.Password)
	csrf := testsupport.CSRFToken(t, rt, "admin-1")

	create := url.Values{
		"id":               {"google-test"},
		"enabled":          {"true"},
		"displayName":      {"Google Test"},
		"clientId":         {"cid-1"},
		"clientSecret":     {"secret-1"},
		"authorizationUrl": {"https://accounts.google.com/o/oauth2/v2/auth"},
		"tokenUrl":         {"https://oauth2.googleapis.com/token"},
		"userInfoUrl":      {"https://openidconnect.googleapis.com/v1/userinfo"},
		"scopes":           {"openid email"},
		"_csrf":            {csrf},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/admin/settings/federation/providers", strings.NewReader(create.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("create status=%d", rec.Code)
	}

	edit := get(t, h, "/sso/admin/settings/federation/providers/edit?id=google-test", cookie)
	if edit.Code != http.StatusOK {
		t.Fatalf("edit page status=%d", edit.Code)
	}
	body := edit.Body.String()
	if !strings.Contains(body, `name="clientId"`) || !strings.Contains(body, "cid-1") {
		t.Fatalf("expected edit form with clientId, got %s", truncate(body, 400))
	}
	if !strings.Contains(body, "/sso/admin/settings/federation") {
		t.Fatal("expected settings nav / cancel link")
	}

	update := url.Values{
		"id":               {"google-test"},
		"enabled":          {"true"},
		"displayName":      {"Google Renamed"},
		"clientId":         {"cid-2"},
		"clientSecret":     {""}, // keep existing
		"authorizationUrl": {"https://accounts.google.com/o/oauth2/v2/auth"},
		"tokenUrl":         {"https://oauth2.googleapis.com/token"},
		"userInfoUrl":      {"https://openidconnect.googleapis.com/v1/userinfo"},
		"scopes":           {"openid email profile"},
		"_csrf":            {testsupport.CSRFToken(t, rt, "admin-1")},
	}
	req2 := httptest.NewRequest(http.MethodPost, "/sso/admin/settings/federation/providers/update", strings.NewReader(update.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Cookie", cookie)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusFound {
		t.Fatalf("update status=%d", rec2.Code)
	}
	if loc := rec2.Header().Get("Location"); !strings.Contains(loc, "flash.settings.providerUpdated") {
		t.Fatalf("location=%q", loc)
	}

	list := get(t, h, "/sso/admin/settings/federation", cookie)
	if !strings.Contains(list.Body.String(), "Google Renamed") || !strings.Contains(list.Body.String(), "cid-2") {
		t.Fatalf("expected updated provider on list, got %s", truncate(list.Body.String(), 500))
	}
	if !strings.Contains(list.Body.String(), "providers/edit?id=") {
		t.Fatal("expected edit link on federation list")
	}
}

func TestAdminSettingsForbiddenForRegularUser(t *testing.T) {
	h := testsupport.NewHandler(t, ssoBase)
	cookie := testsupport.LoginCookie(t, h, "/sso", testsupport.UserEmail, testsupport.Password)
	rec := get(t, h, "/sso/admin/settings/server", cookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
}

