package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gcolin/go-sso/internal/model"
	"golang.org/x/crypto/pbkdf2"
)

const (
	DefaultConfigPath = "sso-server.json"
	EnvConfig         = "DATANODE_SSO_CONFIG"
	AllowInsecureEnv  = "DATANODE_ALLOW_INSECURE_DEFAULTS"
)

// Loader loads and persists AppConfig from a JSON file.
type Loader struct {
	mu   sync.Mutex
	path string
}

func NewLoader(path string) *Loader {
	if path == "" {
		path = os.Getenv(EnvConfig)
	}
	if path == "" {
		path = DefaultConfigPath
	}
	return &Loader{path: path}
}

func (l *Loader) Path() string { return l.path }

func (l *Loader) Load() (*AppConfig, error) {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", l.path, err)
	}
	return Parse(string(data))
}

func Parse(jsonText string) (*AppConfig, error) {
	if err := rejectLegacyMetadataWrapper(jsonText); err != nil {
		return nil, err
	}
	var cfg AppConfig
	if err := json.Unmarshal([]byte(jsonText), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.Defaults()
	if err := Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func rejectLegacyMetadataWrapper(jsonText string) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(jsonText), &root); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if _, ok := root["metadata"]; ok {
		return fmt.Errorf("legacy config format detected: remove the 'metadata' wrapper and use top-level server, security, oauth and users sections")
	}
	return nil
}

func (l *Loader) Save(cfg *AppConfig) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	cfg.Defaults()
	if err := Validate(cfg); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(l.path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	// Write in place: Docker bind mounts reject atomic rename (device or resource busy).
	return os.WriteFile(l.path, data, 0o600)
}

func Validate(cfg *AppConfig) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if strings.TrimSpace(cfg.Server.PublicBaseURL) == "" {
		return fmt.Errorf("server.publicBaseUrl is required")
	}
	if strings.TrimSpace(cfg.Security.SsoPrivateKeyBase64) == "" || strings.TrimSpace(cfg.Security.SsoPublicKeyBase64) == "" {
		return fmt.Errorf("security.ssoPrivateKeyBase64 and security.ssoPublicKeyBase64 are required")
	}
	if err := validateRSAKeyPair(cfg.Security.SsoPrivateKeyBase64, cfg.Security.SsoPublicKeyBase64); err != nil {
		return err
	}
	if cfg.Security.LoginRateLimitMaxAttempts > 0 && cfg.Security.LoginRateLimitWindowSeconds <= 0 {
		return fmt.Errorf("security.loginRateLimitWindowSeconds must be positive when loginRateLimitMaxAttempts is enabled")
	}
	if cfg.Oauth.Clients == nil {
		return fmt.Errorf("oauth.clients is required")
	}
	seenClients := map[string]struct{}{}
	for _, c := range cfg.Oauth.Clients {
		if strings.TrimSpace(c.ClientID) == "" {
			return fmt.Errorf("oauth.clients[].clientId is required")
		}
		if strings.TrimSpace(c.RedirectURI) == "" {
			return fmt.Errorf("oauth.clients[].redirectUri is required")
		}
		if _, ok := seenClients[c.ClientID]; ok {
			return fmt.Errorf("duplicate oauth clientId: %s", c.ClientID)
		}
		seenClients[c.ClientID] = struct{}{}
	}
	if len(cfg.Users) == 0 {
		return fmt.Errorf("users must contain at least one user")
	}
	for _, u := range cfg.Users {
		if strings.TrimSpace(u.ID) == "" || strings.TrimSpace(u.Email) == "" {
			return fmt.Errorf("each user requires id and email")
		}
		if u.RequiresFederatedLogin() {
			if strings.TrimSpace(u.ExternalSubject) == "" {
				return fmt.Errorf("external users require externalSubject: %s", u.Email)
			}
		} else {
			if strings.TrimSpace(u.PasswordHash) == "" {
				return fmt.Errorf("each user requires passwordHash unless authProvider is set")
			}
			if !isValidPasswordHashFormat(u.PasswordHash) {
				return fmt.Errorf("user passwordHash must be a PBKDF2 hash (pbkdf2-sha256$... or pbkdf2-sha512$...): %s", u.Email)
			}
		}
		t := u.AccountType()
		if t != model.TypeUser && t != model.TypeAdmin {
			return fmt.Errorf("user type must be 'user' or 'admin': %s", u.Email)
		}
	}
	if err := validateFederation(&cfg.Federation); err != nil {
		return err
	}
	if err := validateMail(&cfg.Mail); err != nil {
		return err
	}
	return nil
}

func validateFederation(f *FederationConfig) error {
	if f == nil {
		return nil
	}
	seen := map[string]struct{}{}
	for _, p := range f.IdentityProviders {
		if strings.TrimSpace(p.ID) == "" {
			return fmt.Errorf("federation.identityProviders[].id is required")
		}
		if _, ok := seen[p.ID]; ok {
			return fmt.Errorf("duplicate identity provider id: %s", p.ID)
		}
		seen[p.ID] = struct{}{}
		if !p.Enabled {
			continue
		}
		if strings.TrimSpace(p.ClientID) == "" {
			return fmt.Errorf("federation.identityProviders[].clientId is required: %s", p.ID)
		}
		if strings.TrimSpace(p.ClientSecret) == "" {
			return fmt.Errorf("federation.identityProviders[].clientSecret is required: %s", p.ID)
		}
		if strings.TrimSpace(p.AuthorizationURL) == "" {
			return fmt.Errorf("federation.identityProviders[].authorizationUrl is required: %s", p.ID)
		}
		if strings.TrimSpace(p.TokenURL) == "" {
			return fmt.Errorf("federation.identityProviders[].tokenUrl is required: %s", p.ID)
		}
		if strings.TrimSpace(p.UserInfoURL) == "" {
			return fmt.Errorf("federation.identityProviders[].userInfoUrl is required: %s", p.ID)
		}
	}
	if f.DefaultUserType != "" && f.DefaultUserType != model.TypeUser && f.DefaultUserType != model.TypeAdmin {
		return fmt.Errorf("federation.defaultUserType must be 'user' or 'admin'")
	}
	return nil
}

func validateMail(m *MailConfig) error {
	if m == nil || !m.Enabled {
		return nil
	}
	if strings.TrimSpace(m.SmtpHost) == "" {
		return fmt.Errorf("mail.smtpHost is required when mail is enabled")
	}
	if m.SmtpPort <= 0 {
		return fmt.Errorf("mail.smtpPort must be positive when mail is enabled")
	}
	if strings.TrimSpace(m.FromAddress) == "" {
		return fmt.Errorf("mail.fromAddress is required when mail is enabled")
	}
	return nil
}

func validateRSAKeyPair(privB64, pubB64 string) error {
	privDER, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil {
		return fmt.Errorf("invalid RSA key pair in configuration")
	}
	pubDER, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil {
		return fmt.Errorf("invalid RSA key pair in configuration")
	}
	privAny, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return fmt.Errorf("invalid RSA key pair in configuration: %w", err)
	}
	priv, ok := privAny.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("invalid RSA key pair in configuration: not RSA private key")
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return fmt.Errorf("invalid RSA key pair in configuration: %w", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid RSA key pair in configuration: not RSA public key")
	}
	if priv.N.Cmp(pub.N) != 0 {
		return fmt.Errorf("RSA private and public keys do not match")
	}
	return nil
}

// HashPassword creates a Datanode-native pbkdf2-sha256 hash (delegates same algorithm as security package).
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2.Key([]byte(password), salt, 210000, 32, sha256.New)
	return fmt.Sprintf("pbkdf2-sha256$210000$%s$%s",
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(dk),
	), nil
}

func isValidPasswordHashFormat(encodedHash string) bool {
	if strings.TrimSpace(encodedHash) == "" {
		return false
	}
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 4 {
		return false
	}
	prefix := strings.ToLower(parts[0])
	if prefix != "pbkdf2-sha256" && prefix != "pbkdf2-sha512" {
		return false
	}
	if _, err := base64.StdEncoding.DecodeString(parts[2]); err != nil {
		return false
	}
	hashBytes, err := base64.StdEncoding.DecodeString(parts[3])
	return err == nil && len(hashBytes) > 0
}

func GenerateRSAKeyPairBase64() (privB64, pubB64 string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(privDER), base64.StdEncoding.EncodeToString(pubDER), nil
}

func (l *Loader) InitConfigFile(path string) error {
	if path == "" {
		path = l.path
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if st, err := os.Stat(abs); err == nil && st.Mode().IsRegular() {
		return fmt.Errorf("config file already exists: %s", abs)
	}
	l.path = abs
	cfg, err := BuildDefaultConfig()
	if err != nil {
		return err
	}
	return l.Save(cfg)
}

func (l *Loader) EnsureSigningKeys(path string) error {
	if path == "" {
		path = l.path
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	l.path = abs
	data, err := os.ReadFile(abs)
	if err != nil {
		return err
	}
	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	cfg.Defaults()
	if strings.TrimSpace(cfg.Security.SsoPrivateKeyBase64) != "" && strings.TrimSpace(cfg.Security.SsoPublicKeyBase64) != "" {
		if err := validateRSAKeyPair(cfg.Security.SsoPrivateKeyBase64, cfg.Security.SsoPublicKeyBase64); err == nil {
			return nil
		}
	}
	priv, pub, err := GenerateRSAKeyPairBase64()
	if err != nil {
		return err
	}
	cfg.Security.SsoPrivateKeyBase64 = priv
	cfg.Security.SsoPublicKeyBase64 = pub
	return l.Save(&cfg)
}

func BuildDefaultConfig() (*AppConfig, error) {
	priv, pub, err := GenerateRSAKeyPairBase64()
	if err != nil {
		return nil, err
	}
	hash, err := HashPassword("admin123")
	if err != nil {
		return nil, err
	}
	cfg := &AppConfig{
		Server: ServerConfig{
			Host:          "0.0.0.0",
			Port:          8080,
			PublicBaseURL: "http://localhost:8080/sso",
			Title:         "Datanode SSO",
			DefaultLocale: "fr",
		},
		Security: SecurityConfig{
			SessionCookieName:           "datanode_sso_session",
			SessionTtlMinutes:           720,
			SsoPrivateKeyBase64:         priv,
			SsoPublicKeyBase64:          pub,
			LoginRateLimitMaxAttempts:   10,
			LoginRateLimitWindowSeconds: 300,
			EmailVerificationTtlHours:   48,
		},
		Oauth: OAuthConfig{
			AuthorizationCodeTtlSeconds: 300,
			AccessTokenTtlSeconds:       3600,
			Clients:                     []model.OAuthClient{},
		},
		Federation: FederationConfig{DefaultUserType: model.TypeUser},
		Mail:       MailConfig{SmtpHost: "localhost", SmtpPort: 587, FromName: "Datanode SSO", StartTLS: true},
		Users: []model.User{{
			ID:           "admin-1",
			Email:        "admin@example.com",
			PasswordHash: hash,
			Name:         "Admin",
			Type:         model.TypeAdmin,
		}},
	}
	cfg.Defaults()
	return cfg, nil
}
