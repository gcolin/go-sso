package config

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/gcolin/go-sso/internal/model"
)

// AppConfig mirrors the Java AppConfig JSON schema (camelCase).
type AppConfig struct {
	Server     ServerConfig           `json:"server"`
	Security   SecurityConfig         `json:"security"`
	Oauth      OAuthConfig            `json:"oauth"`
	Federation FederationConfig       `json:"federation"`
	Mail       MailConfig             `json:"mail"`
	Users []model.User `json:"users"`
}

type ServerConfig struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	PublicBaseURL string `json:"publicBaseUrl"`
	Title         string `json:"title"`
	Realm         string `json:"realm,omitempty"`
	DefaultLocale string `json:"defaultLocale"`
	DefaultTheme  string `json:"defaultTheme,omitempty"`
	ThemesDir     string `json:"themesDir,omitempty"`
}

func (s *ServerConfig) EffectiveTitle() string {
	if s == nil || s.Title == "" {
		return "Datanode SSO"
	}
	return s.Title
}

// ResolveThemesDir returns the on-disk themes directory.
// Empty themesDir → <configDir>/themes. Relative themesDir is resolved against the config file directory.
func ResolveThemesDir(configPath, themesDir string) string {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		configPath = "sso-server.json"
	}
	absConfig, err := filepath.Abs(configPath)
	if err != nil {
		absConfig = configPath
	}
	configDir := filepath.Dir(absConfig)
	themesDir = strings.TrimSpace(themesDir)
	if themesDir == "" {
		return filepath.Join(configDir, "themes")
	}
	if filepath.IsAbs(themesDir) {
		return themesDir
	}
	return filepath.Join(configDir, themesDir)
}


// ContextPath returns the URL path prefix from publicBaseUrl (e.g. "/sso"), or "" if none.
func (s *ServerConfig) ContextPath() string {
	if s == nil || s.PublicBaseURL == "" {
		return "/sso"
	}
	u, err := url.Parse(s.PublicBaseURL)
	if err != nil || u.Path == "" || u.Path == "/" {
		return ""
	}
	p := strings.TrimSuffix(u.Path, "/")
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

type SecurityConfig struct {
	SessionCookieName           string `json:"sessionCookieName"`
	SessionCookieSecure         bool   `json:"sessionCookieSecure"`
	SessionTtlMinutes           int64  `json:"sessionTtlMinutes"`
	SsoPrivateKeyBase64         string `json:"ssoPrivateKeyBase64"`
	SsoPublicKeyBase64          string `json:"ssoPublicKeyBase64"`
	LoginRateLimitMaxAttempts   int    `json:"loginRateLimitMaxAttempts"`
	LoginRateLimitWindowSeconds int64  `json:"loginRateLimitWindowSeconds"`
	EmailVerificationTtlHours   int64  `json:"emailVerificationTtlHours"`
	DefaultUserMaxStorageBytes  int64  `json:"defaultUserMaxStorageBytes"`
	PublicRegistrationEnabled   bool   `json:"publicRegistrationEnabled"`
}

func (s *SecurityConfig) EffectiveSessionCookieName() string {
	if s == nil || s.SessionCookieName == "" {
		return "datanode_sso_session"
	}
	return s.SessionCookieName
}

func (s *SecurityConfig) EffectiveSessionTtlMinutes() int64 {
	if s == nil || s.SessionTtlMinutes <= 0 {
		return 720
	}
	return s.SessionTtlMinutes
}

func (s *SecurityConfig) EffectiveEmailVerificationTtlHours() int64 {
	if s == nil || s.EmailVerificationTtlHours <= 0 {
		return 48
	}
	return s.EmailVerificationTtlHours
}

type OAuthConfig struct {
	AuthorizationCodeTtlSeconds int64               `json:"authorizationCodeTtlSeconds"`
	AccessTokenTtlSeconds       int64               `json:"accessTokenTtlSeconds"`
	Clients                     []model.OAuthClient `json:"clients"`
}

func (o *OAuthConfig) EffectiveAuthCodeTTL() int64 {
	if o == nil || o.AuthorizationCodeTtlSeconds <= 0 {
		return 300
	}
	return o.AuthorizationCodeTtlSeconds
}

func (o *OAuthConfig) EffectiveAccessTokenTTL() int64 {
	if o == nil || o.AccessTokenTtlSeconds <= 0 {
		return 3600
	}
	return o.AccessTokenTtlSeconds
}

type FederationConfig struct {
	AutoProvision     bool                     `json:"autoProvision"`
	DefaultUserType   string                   `json:"defaultUserType"`
	IdentityProviders []model.IdentityProvider `json:"identityProviders"`
}

type MailConfig struct {
	Enabled     bool   `json:"enabled"`
	SmtpHost    string `json:"smtpHost"`
	SmtpPort    int    `json:"smtpPort"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	FromAddress string `json:"fromAddress,omitempty"`
	FromName    string `json:"fromName,omitempty"`
	StartTLS    bool   `json:"startTls"`
}

// Defaults applies Java-like defaults for missing nested objects.
func (c *AppConfig) Defaults() {
	if c.Server.Host == "" {
		c.Server.Host = "127.0.0.1"
	}
	if c.Server.Port == 0 {
		c.Server.Port = 8080
	}
	if c.Server.PublicBaseURL == "" {
		c.Server.PublicBaseURL = "http://localhost:8080/sso"
	}
	if c.Server.Title == "" {
		c.Server.Title = "Datanode SSO"
	}
	if c.Server.DefaultLocale == "" {
		c.Server.DefaultLocale = "fr"
	}
	if c.Security.SessionCookieName == "" {
		c.Security.SessionCookieName = "datanode_sso_session"
	}
	if c.Security.SessionTtlMinutes <= 0 {
		c.Security.SessionTtlMinutes = 720
	}
	if c.Security.LoginRateLimitMaxAttempts == 0 {
		c.Security.LoginRateLimitMaxAttempts = 10
	}
	if c.Security.LoginRateLimitWindowSeconds == 0 {
		c.Security.LoginRateLimitWindowSeconds = 300
	}
	if c.Security.EmailVerificationTtlHours <= 0 {
		c.Security.EmailVerificationTtlHours = 48
	}
	if c.Oauth.AuthorizationCodeTtlSeconds <= 0 {
		c.Oauth.AuthorizationCodeTtlSeconds = 300
	}
	if c.Oauth.AccessTokenTtlSeconds <= 0 {
		c.Oauth.AccessTokenTtlSeconds = 3600
	}
	if c.Oauth.Clients == nil {
		c.Oauth.Clients = []model.OAuthClient{}
	}
	if c.Federation.DefaultUserType == "" {
		c.Federation.DefaultUserType = model.TypeUser
	}
	if c.Federation.IdentityProviders == nil {
		c.Federation.IdentityProviders = []model.IdentityProvider{}
	}
	if c.Mail.SmtpHost == "" {
		c.Mail.SmtpHost = "localhost"
	}
	if c.Mail.SmtpPort == 0 {
		c.Mail.SmtpPort = 587
	}
	if c.Mail.FromName == "" {
		c.Mail.FromName = "Datanode SSO"
	}
	// StartTLS defaults to true in Java; zero value is false — set on init-config.
	if c.Users == nil {
		c.Users = []model.User{}
	}
	for i := range c.Users {
		if c.Users[i].Type == "" {
			c.Users[i].Type = model.TypeUser
		}
	}
	for i := range c.Federation.IdentityProviders {
		p := &c.Federation.IdentityProviders[i]
		if p.Scopes == "" {
			p.Scopes = "openid email profile"
		}
		if p.EmailClaim == "" {
			p.EmailClaim = "email"
		}
		if p.NameClaim == "" {
			p.NameClaim = "name"
		}
		if p.SubjectClaim == "" {
			p.SubjectClaim = "sub"
		}
	}
}
