package model

import (
	"strings"
	"unicode"
)

// User is a local or federated SSO account persisted in AppConfig.
type User struct {
	ID              string `json:"id"`
	Email           string `json:"email"`
	PasswordHash    string `json:"passwordHash,omitempty"`
	Name            string `json:"name,omitempty"`
	Type            string `json:"type"`
	TotpSecret      string `json:"totpSecret,omitempty"`
	AuthProvider    string `json:"authProvider,omitempty"`
	ExternalSubject string `json:"externalSubject,omitempty"`
	// EmailVerified is a pointer so null means "treated as verified" (Java parity).
	EmailVerified   *bool  `json:"emailVerified,omitempty"`
	MaxStorageBytes int64  `json:"maxStorageBytes,omitempty"`
}

const (
	TypeUser  = "user"
	TypeAdmin = "admin"
)

func (u *User) AccountType() string {
	if u == nil || u.Type == "" {
		return TypeUser
	}
	return u.Type
}

func (u *User) IsAdmin() bool {
	return u.AccountType() == TypeAdmin
}

func (u *User) PlatformRoles() []string {
	if u.IsAdmin() {
		return []string{"platform:user", "platform:admin"}
	}
	return []string{"platform:user"}
}

func (u *User) IsTotpEnabled() bool {
	return u != nil && u.TotpSecret != ""
}

func (u *User) HasLocalPassword() bool {
	return u != nil && u.PasswordHash != ""
}

func (u *User) RequiresFederatedLogin() bool {
	return u != nil && u.AuthProvider != "" && !u.HasLocalPassword()
}

func (u *User) IsEmailVerified() bool {
	if u == nil || u.EmailVerified == nil {
		return true
	}
	return *u.EmailVerified
}

func (u *User) EffectiveMaxStorageBytes(defaultBytes int64) int64 {
	if u != nil && u.MaxStorageBytes > 0 {
		return u.MaxStorageBytes
	}
	if defaultBytes > 0 {
		return defaultBytes
	}
	return 0
}

// OAuthClient is a registered OAuth 2.0 client.
type OAuthClient struct {
	ClientID     string `json:"clientId"`
	DisplayName  string `json:"displayName,omitempty"`
	RedirectURI  string `json:"redirectUri"`
	ClientSecret string `json:"clientSecret,omitempty"`
	Theme        string `json:"theme,omitempty"`
}

func (c *OAuthClient) IsConfidential() bool {
	return c != nil && c.ClientSecret != ""
}

// DisplayLabel is the user-facing name (displayName, else a softened clientId).
func (c *OAuthClient) DisplayLabel() string {
	if c == nil {
		return ""
	}
	if n := strings.TrimSpace(c.DisplayName); n != "" {
		return n
	}
	return HumanizeClientID(c.ClientID)
}

// HumanizeClientID turns "ticket-test" into "Ticket Test" for consent UI fallback.
func HumanizeClientID(clientID string) string {
	s := strings.TrimSpace(clientID)
	if s == "" {
		return s
	}
	s = strings.ReplaceAll(s, "-", " ")
	s = strings.ReplaceAll(s, "_", " ")
	parts := strings.Fields(s)
	for i, p := range parts {
		runes := []rune(strings.ToLower(p))
		if len(runes) == 0 {
			continue
		}
		runes[0] = unicode.ToUpper(runes[0])
		parts[i] = string(runes)
	}
	return strings.Join(parts, " ")
}

// IdentityProvider is an external OIDC/OAuth IdP (federation; stored for schema parity).
type IdentityProvider struct {
	ID               string `json:"id"`
	Enabled          bool   `json:"enabled"`
	DisplayName      string `json:"displayName,omitempty"`
	Logo             string `json:"logo,omitempty"`
	ClientID         string `json:"clientId,omitempty"`
	ClientSecret     string `json:"clientSecret,omitempty"`
	AuthorizationURL string `json:"authorizationUrl,omitempty"`
	TokenURL         string `json:"tokenUrl,omitempty"`
	UserInfoURL      string `json:"userInfoUrl,omitempty"`
	Scopes           string `json:"scopes,omitempty"`
	EmailClaim       string `json:"emailClaim,omitempty"`
	NameClaim        string `json:"nameClaim,omitempty"`
	SubjectClaim     string `json:"subjectClaim,omitempty"`
	RedirectURI      string `json:"redirectUri,omitempty"`
}

// AuthorizationCode is an issued auth code (stored by SHA-256 hex of the raw code).
type AuthorizationCode struct {
	CodeHash            string
	ClientID            string
	UserID              string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	Nonce               string
	ExpiresAt           int64 // unix seconds
	Consumed            bool
}

// AuthorizationRequest is a pending consent request.
type AuthorizationRequest struct {
	RequestID           string
	UserID              string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	ResponseType        string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           int64
}
