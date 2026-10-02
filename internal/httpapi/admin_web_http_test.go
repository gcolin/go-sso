package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gcolin/go-sso/internal/testsupport"
)

// Ports WebResourceTest admin HTML assertions over live mux (Java parity).

func TestAdminClientsRendersForAdmin(t *testing.T) {
	h := testsupport.NewHandler(t, ssoBase)
	cookie := testsupport.LoginCookie(t, h, "/sso", testsupport.AdminEmail, testsupport.Password)
	rec := get(t, h, "/sso/admin/clients", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "Bienvenue") {
		t.Fatal("got home page instead of admin clients")
	}
	if !strings.Contains(body, "/sso/admin/clients/new") {
		t.Fatal("expected new client link")
	}
	if !strings.Contains(body, "/sso/admin/settings/server") {
		t.Fatal("expected settings nav on clients page")
	}
}

func TestAdminClientsForbiddenForRegularUser(t *testing.T) {
	h := testsupport.NewHandler(t, ssoBase)
	cookie := testsupport.LoginCookie(t, h, "/sso", testsupport.UserEmail, testsupport.Password)
	rec := get(t, h, "/sso/admin/clients", cookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "administrat") && !strings.Contains(rec.Body.String(), "admin") {
		t.Fatalf("expected admin-only error page, got %s", truncate(rec.Body.String(), 200))
	}
}

func TestAdminClientsRedirectsAnonymousToLogin(t *testing.T) {
	h := testsupport.NewHandler(t, ssoBase)
	rec := get(t, h, "/sso/admin/clients", "")
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/sso/login") {
		t.Fatalf("Location=%q", loc)
	}
}

func TestAdminRootRedirectsToSettings(t *testing.T) {
	h := testsupport.NewHandler(t, ssoBase)
	cookie := testsupport.LoginCookie(t, h, "/sso", testsupport.AdminEmail, testsupport.Password)
	rec := get(t, h, "/sso/admin", cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/sso/admin/settings" {
		t.Fatalf("Location=%q", loc)
	}
}

func TestAdminUsersRendersForAdmin(t *testing.T) {
	h := testsupport.NewHandler(t, ssoBase)
	cookie := testsupport.LoginCookie(t, h, "/sso", testsupport.AdminEmail, testsupport.Password)
	rec := get(t, h, "/sso/admin/users", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, truncate(rec.Body.String(), 200))
	}
	body := rec.Body.String()
	if strings.Contains(body, "Bienvenue") {
		t.Fatal("got home page instead of admin users")
	}
	if !strings.Contains(body, testsupport.AdminEmail) && !strings.Contains(body, "/sso/admin/users/new") {
		t.Fatalf("expected users page content, got %s", truncate(body, 240))
	}
}

func TestProfileRendersForAuthenticatedUser(t *testing.T) {
	h := testsupport.NewHandler(t, ssoBase)
	cookie := testsupport.LoginCookie(t, h, "/sso", testsupport.UserEmail, testsupport.Password)
	rec := get(t, h, "/sso/profile", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, truncate(rec.Body.String(), 200))
	}
	if !strings.Contains(rec.Body.String(), testsupport.UserEmail) {
		t.Fatal("expected profile page with user email")
	}
}

func TestProfileRedirectsAnonymousToLogin(t *testing.T) {
	h := testsupport.NewHandler(t, ssoBase)
	rec := get(t, h, "/sso/profile", "")
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/sso/login") {
		t.Fatalf("Location=%q", loc)
	}
}

func TestAdminClientCreateSucceeds(t *testing.T) {
	rt, h := testsupport.NewRuntime(t, ssoBase)
	cookie := testsupport.LoginCookie(t, h, "/sso", testsupport.AdminEmail, testsupport.Password)
	form := url.Values{
		"clientId":      {"created-client-1"},
		"redirectUri":   {"http://localhost/callback"},
		"confidential":  {"true"},
		"_csrf":         {testsupport.CSRFToken(t, rt, "admin-1")},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/sso/admin/clients", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "created-client-1") {
		t.Fatalf("expected clientCreated page, got %s", truncate(rec.Body.String(), 240))
	}
}

func get(t *testing.T, h http.Handler, path, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
