package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/testsupport"
)

const ssoBase = "http://localhost:8080/sso"

func TestAuthorizeUnderSsoContextPath(t *testing.T) {
	h := testsupport.NewHandler(t, ssoBase)
	q := url.Values{
		"client_id":     {testsupport.ChessClientID},
		"redirect_uri":  {testsupport.ChessRedirect},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {"L2Rhc2hib2FyZA=="},
	}
	req := httptest.NewRequest(http.MethodGet, "/sso/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Fatalf("got 404 for /sso/oauth/authorize")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected login page, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/oauth/authorize?") || !strings.Contains(body, `name="returnUrl"`) {
		t.Fatalf("expected authorize returnUrl on login page, got %s", truncate(body, 300))
	}
}

func TestAdminClientsUnderSsoContextPath(t *testing.T) {
	h := testsupport.NewHandler(t, ssoBase)
	cookie := testsupport.LoginCookie(t, h, "/sso", testsupport.AdminEmail, testsupport.Password)
	req := httptest.NewRequest(http.MethodGet, "/sso/admin/clients", nil)
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "Bienvenue") {
		t.Fatal("admin clients rendered home page")
	}
	if !strings.Contains(body, "/admin/clients/new") {
		t.Fatalf("missing new-client link in: %s", truncate(body, 240))
	}
}

func TestRootRedirectsToContextPath(t *testing.T) {
	h := testsupport.NewHandler(t, ssoBase)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/sso/" {
		t.Fatalf("status=%d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestContextPathFromConfig(t *testing.T) {
	cfg := &config.ServerConfig{PublicBaseURL: ssoBase}
	if got := cfg.ContextPath(); got != "/sso" {
		t.Fatalf("ContextPath=%q", got)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
