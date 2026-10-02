package testsupport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/httpapi"
	"github.com/gcolin/go-sso/internal/model"
	"github.com/gcolin/go-sso/internal/runtime"
	"github.com/gcolin/go-sso/internal/security"
)

var csrfTokenPattern = regexp.MustCompile(`name="_csrf"\s+value="([^"]+)"`)

// ExtractCSRF returns the _csrf form value from an HTML body.
func ExtractCSRF(t *testing.T, html string) string {
	t.Helper()
	m := csrfTokenPattern.FindStringSubmatch(html)
	if len(m) != 2 {
		t.Fatalf("missing _csrf in html")
	}
	return m[1]
}

const (
	AdminEmail    = "admin@example.com"
	UserEmail     = "user@example.com"
	Password      = "SuperPassword123"
	TestClientID  = "test-client"
	TestRedirect  = "http://localhost:8080/node/auth/callback"
	ChessClientID = "chessprogress"
	ChessRedirect = "http://localhost:8081/keycloak-callback"
)

// NewHandler builds an SSO HTTP handler with an in-memory fixture (Java SsoTestServer parity).
func NewHandler(t *testing.T, publicBaseURL string) http.Handler {
	t.Helper()
	_, h := NewRuntime(t, publicBaseURL)
	return h
}

// NewRuntime builds a Runtime + handler sharing the same signing keys (for CSRF helpers).
func NewRuntime(t *testing.T, publicBaseURL string) (*runtime.Runtime, http.Handler) {
	t.Helper()
	cfg := NewConfig(t, publicBaseURL)
	path := filepath.Join(t.TempDir(), "sso-server.json")
	loader := config.NewLoader(path)
	if err := loader.Save(cfg); err != nil {
		t.Fatalf("save fixture: %v", err)
	}
	rt, err := runtime.New(cfg, loader)
	if err != nil {
		t.Fatalf("runtime: %v", err)
	}
	return rt, httpapi.New(rt).Handler()
}

// CSRFToken returns a signed CSRF JWT bound to userID (empty for anonymous forms).
func CSRFToken(t *testing.T, rt *runtime.Runtime, userID string) string {
	t.Helper()
	tok, err := rt.JWT.CreateCsrfToken(userID)
	if err != nil {
		t.Fatalf("csrf: %v", err)
	}
	return tok
}

func NewConfig(t *testing.T, publicBaseURL string) *config.AppConfig {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal priv: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	hash, err := security.HashPassword(Password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	cfg := &config.AppConfig{
		Server: config.ServerConfig{
			Host:          "127.0.0.1",
			Port:          0,
			PublicBaseURL: publicBaseURL,
			Title:         "Test SSO",
			DefaultLocale: "fr",
		},
		Security: config.SecurityConfig{
			SessionCookieName:         "datanode_sso_session",
			SessionTtlMinutes:         720,
			PublicRegistrationEnabled: true,
			SsoPrivateKeyBase64:       base64.StdEncoding.EncodeToString(privDER),
			SsoPublicKeyBase64:        base64.StdEncoding.EncodeToString(pubDER),
		},
		Oauth: config.OAuthConfig{
			AuthorizationCodeTtlSeconds: 300,
			AccessTokenTtlSeconds:       3600,
			Clients: []model.OAuthClient{
				{ClientID: TestClientID, DisplayName: "Test app", RedirectURI: TestRedirect},
				{ClientID: ChessClientID, DisplayName: "Chess Progress", RedirectURI: ChessRedirect},
				{ClientID: "machine-client", RedirectURI: "http://localhost:3000/oauth/callback", ClientSecret: "machine-secret"},
			},
		},
		Users: []model.User{
			{ID: "admin-1", Email: AdminEmail, Name: "Admin User", Type: "admin", PasswordHash: hash},
			{ID: "user-1", Email: UserEmail, Name: "Demo User", Type: "user", PasswordHash: hash},
		},
	}
	cfg.Defaults()
	return cfg
}

func LoginCookie(t *testing.T, h http.Handler, basePath, email, password string) string {
	t.Helper()
	body := `{"email":"` + email + `","password":"` + password + `"}`
	req := httptest.NewRequest(http.MethodPost, basePath+"/api/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "datanode_sso_session" {
			return c.Name + "=" + c.Value
		}
	}
	t.Fatal("missing session cookie")
	return ""
}
