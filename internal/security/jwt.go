package security

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/gcolin/go-sso/internal/config"
)

const (
	TokenTypeSession             = "sso_session"
	TokenTypeAccess              = "access_token"
	TokenTypePending2FA          = "pending_2fa"
	TokenTypeEmailVerification   = "email_verification"
	TokenTypePendingRegistration = "pending_registration"
	TokenTypeCSRF                = "sso_csrf"
	KeyID                        = "sso-rsa-key"
	pending2FATTLSeconds         = 300
)

// JwtService signs and verifies SSO JWTs (RS256, wire-compatible with Java).
type JwtService struct {
	cfg        *config.AppConfig
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
}

func NewJwtService(cfg *config.AppConfig) (*JwtService, error) {
	privDER, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.Security.SsoPrivateKeyBase64))
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	pubDER, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.Security.SsoPublicKeyBase64))
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	privAny, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return nil, err
	}
	priv, ok := privAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return nil, err
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	issuer := strings.TrimRight(cfg.Server.PublicBaseURL, "/")
	return &JwtService{cfg: cfg, privateKey: priv, publicKey: pub, issuer: issuer}, nil
}

func (j *JwtService) Issuer() string {
	if j.cfg != nil && strings.TrimSpace(j.cfg.Server.PublicBaseURL) != "" {
		return strings.TrimRight(j.cfg.Server.PublicBaseURL, "/")
	}
	return j.issuer
}

func (j *JwtService) CreateSessionToken(userID, email string, roles []string) (string, error) {
	return j.CreateSessionTokenForClient(userID, email, roles, "")
}

func (j *JwtService) CreateSessionTokenForClient(userID, email string, roles []string, clientID string) (string, error) {
	if roles == nil {
		roles = []string{"platform:user"}
	}
	now := time.Now().Unix()
	claims := map[string]any{
		"jti":   newID(),
		"iss":   j.Issuer(),
		"sub":   userID,
		"email": email,
		"roles": roles,
		"type":  TokenTypeSession,
		"iat":   now,
		"exp":   now + j.cfg.Security.EffectiveSessionTtlMinutes()*60,
	}
	if id := strings.TrimSpace(clientID); id != "" {
		claims["client_id"] = id
	}
	return j.sign(claims)
}

func (j *JwtService) CreateAccessToken(userID, email, name, scope string, roles []string) (string, error) {
	if roles == nil {
		roles = []string{"platform:user"}
	}
	now := time.Now().Unix()
	claims := map[string]any{
		"jti":                newID(),
		"iss":                j.Issuer(),
		"sub":                userID,
		"email":              email,
		"name":               name,
		"preferred_username": email,
		"scope":              scope,
		"roles":              roles,
		"type":               TokenTypeAccess,
		"iat":                now,
		"exp":                now + j.cfg.Oauth.EffectiveAccessTokenTTL(),
	}
	return j.sign(claims)
}

// CreateIDToken builds an OIDC ID Token (RS256) for the given client audience.
// Claims follow OpenID Connect Core based on requested scopes.
func (j *JwtService) CreateIDToken(userID, email, name, clientID, scope, nonce string, emailVerified bool) (string, error) {
	now := time.Now().Unix()
	claims := map[string]any{
		"jti": newID(),
		"iss": j.Issuer(),
		"sub": userID,
		"aud": clientID,
		"iat": now,
		"exp": now + j.cfg.Oauth.EffectiveAccessTokenTTL(),
	}
	if strings.TrimSpace(nonce) != "" {
		claims["nonce"] = nonce
	}
	for _, s := range strings.Fields(scope) {
		switch s {
		case "email":
			claims["email"] = email
			claims["email_verified"] = emailVerified
		case "profile":
			claims["name"] = name
			claims["preferred_username"] = email
		}
	}
	return j.sign(claims)
}

func (j *JwtService) CreateClientCredentialsAccessToken(clientID, scope string) (string, error) {
	now := time.Now().Unix()
	claims := map[string]any{
		"jti":   newID(),
		"iss":   j.Issuer(),
		"sub":   clientID,
		"scope": scope,
		"type":  TokenTypeAccess,
		"iat":   now,
		"exp":   now + j.cfg.Oauth.EffectiveAccessTokenTTL(),
	}
	return j.sign(claims)
}

func (j *JwtService) CreatePending2FAToken(userID, email, returnURL string) (string, error) {
	if returnURL == "" {
		returnURL = "/"
	}
	now := time.Now().Unix()
	claims := map[string]any{
		"jti":       newID(),
		"iss":       j.Issuer(),
		"sub":       userID,
		"email":     email,
		"returnUrl": returnURL,
		"type":      TokenTypePending2FA,
		"iat":       now,
		"exp":       now + pending2FATTLSeconds,
	}
	return j.sign(claims)
}

func (j *JwtService) CreateEmailVerificationToken(userID, email string) (string, error) {
	now := time.Now().Unix()
	claims := map[string]any{
		"jti":   newID(),
		"iss":   j.Issuer(),
		"sub":   userID,
		"email": email,
		"type":  TokenTypeEmailVerification,
		"iat":   now,
		"exp":   now + j.cfg.Security.EffectiveEmailVerificationTtlHours()*3600,
	}
	return j.sign(claims)
}

func (j *JwtService) CreatePendingRegistrationToken(userID, email, returnURL string) (string, error) {
	if returnURL == "" {
		returnURL = "/"
	}
	now := time.Now().Unix()
	claims := map[string]any{
		"jti":       newID(),
		"iss":       j.Issuer(),
		"sub":       userID,
		"email":     email,
		"returnUrl": returnURL,
		"type":      TokenTypePendingRegistration,
		"iat":       now,
		"exp":       now + j.cfg.Security.EffectiveEmailVerificationTtlHours()*3600,
	}
	return j.sign(claims)
}

// CreateCsrfToken signs a CSRF JWT bound to userID (empty for anonymous forms).
// No server-side storage: validation is signature + subject match against the session.
func (j *JwtService) CreateCsrfToken(userID string) (string, error) {
	now := time.Now().Unix()
	claims := map[string]any{
		"jti":  newID(),
		"iss":  j.Issuer(),
		"sub":  strings.TrimSpace(userID),
		"type": TokenTypeCSRF,
		"iat":  now,
		"exp":  now + j.cfg.Security.EffectiveSessionTtlMinutes()*60,
	}
	return j.sign(claims)
}

// ValidateCsrfToken verifies a CSRF JWT and ensures its subject matches expectedUserID.
func (j *JwtService) ValidateCsrfToken(token, expectedUserID string) error {
	claims, err := j.verify(token, TokenTypeCSRF)
	if err != nil {
		return err
	}
	if claimString(claims, "sub") != strings.TrimSpace(expectedUserID) {
		return fmt.Errorf("csrf subject mismatch")
	}
	return nil
}

type SessionClaims struct {
	UserID   string
	Email    string
	Roles    []string
	ClientID string
}

type AccessTokenClaims struct {
	UserID            string
	Subject           string
	Email             string
	Name              string
	PreferredUsername string
	Scope             string
	Roles             []string
}

type Pending2FAClaims struct {
	UserID    string
	Email     string
	ReturnURL string
}

func (j *JwtService) ParseSessionToken(token string) (*SessionClaims, error) {
	claims, err := j.verify(token, TokenTypeSession)
	if err != nil {
		return nil, err
	}
	return &SessionClaims{
		UserID:   claimString(claims, "sub"),
		Email:    claimString(claims, "email"),
		Roles:    claimStringSlice(claims, "roles"),
		ClientID: claimString(claims, "client_id"),
	}, nil
}

func (j *JwtService) ParseAccessToken(token string) (*AccessTokenClaims, error) {
	claims, err := j.verify(token, TokenTypeAccess)
	if err != nil {
		return nil, err
	}
	return &AccessTokenClaims{
		UserID:            claimString(claims, "sub"),
		Subject:           claimString(claims, "sub"),
		Email:             claimString(claims, "email"),
		Name:              claimString(claims, "name"),
		PreferredUsername: claimString(claims, "preferred_username"),
		Scope:             claimString(claims, "scope"),
		Roles:             claimStringSlice(claims, "roles"),
	}, nil
}

func (j *JwtService) ParsePending2FAToken(token string) (*Pending2FAClaims, error) {
	claims, err := j.verify(token, TokenTypePending2FA)
	if err != nil {
		return nil, err
	}
	returnURL := claimString(claims, "returnUrl")
	if returnURL == "" {
		returnURL = "/"
	}
	return &Pending2FAClaims{
		UserID:    claimString(claims, "sub"),
		Email:     claimString(claims, "email"),
		ReturnURL: returnURL,
	}, nil
}

type EmailVerificationClaims struct {
	UserID string
	Email  string
}

func (j *JwtService) ParseEmailVerificationToken(token string) (*EmailVerificationClaims, error) {
	claims, err := j.verify(token, TokenTypeEmailVerification)
	if err != nil {
		return nil, err
	}
	userID := claimString(claims, "sub")
	email := claimString(claims, "email")
	if userID == "" || email == "" {
		return nil, fmt.Errorf("invalid email verification token")
	}
	return &EmailVerificationClaims{UserID: userID, Email: email}, nil
}

type PendingRegistrationClaims struct {
	UserID    string
	Email     string
	ReturnURL string
}

func (j *JwtService) ParsePendingRegistrationToken(token string) (*PendingRegistrationClaims, error) {
	claims, err := j.verify(token, TokenTypePendingRegistration)
	if err != nil {
		return nil, err
	}
	returnURL := claimString(claims, "returnUrl")
	if returnURL == "" {
		returnURL = "/"
	}
	userID := claimString(claims, "sub")
	email := claimString(claims, "email")
	if userID == "" || email == "" {
		return nil, fmt.Errorf("invalid pending registration token")
	}
	return &PendingRegistrationClaims{UserID: userID, Email: email, ReturnURL: returnURL}, nil
}

// IsConfidentialClientAccessToken reports whether an access token is a client_credentials token
// (no email claim).
func (c *AccessTokenClaims) IsConfidentialClientAccessToken() bool {
	return c != nil && strings.TrimSpace(c.Email) == ""
}

func (j *JwtService) JWKS() map[string]any {
	n := base64.RawURLEncoding.EncodeToString(j.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(j.publicKey.E)).Bytes())
	return map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": KeyID,
			"use": "sig",
			"alg": "RS256",
			"n":   n,
			"e":   e,
		}},
	}
}

func (j *JwtService) JWKSDocument() map[string]any {
	return j.JWKS()
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func (j *JwtService) sign(claims map[string]any) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": KeyID}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encHeader := base64.RawURLEncoding.EncodeToString(hb)
	encPayload := base64.RawURLEncoding.EncodeToString(pb)
	signingInput := encHeader + "." + encPayload
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, j.privateKey, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (j *JwtService) verify(token, expectedType string) (map[string]any, error) {
	token = NormalizeBearer(token)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header map[string]any
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, err
	}
	if claimString(header, "alg") != "RS256" {
		return nil, fmt.Errorf("unexpected alg")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	signingInput := parts[0] + "." + parts[1]
	sum := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(j.publicKey, crypto.SHA256, sum[:], sig); err != nil {
		return nil, fmt.Errorf("invalid signature")
	}
	if claimString(claims, "iss") != j.Issuer() {
		return nil, fmt.Errorf("invalid issuer")
	}
	exp := claimInt64(claims, "exp")
	if exp == 0 || time.Now().Unix() >= exp {
		return nil, fmt.Errorf("token expired")
	}
	if claimString(claims, "type") != expectedType {
		return nil, fmt.Errorf("unexpected token type")
	}
	return claims, nil
}

// NormalizeBearer strips an optional "Bearer " prefix.
func NormalizeBearer(token string) string {
	token = strings.TrimSpace(token)
	if len(token) >= 7 && strings.EqualFold(token[:7], "Bearer ") {
		return strings.TrimSpace(token[7:])
	}
	return token
}

func claimString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if ok {
		return s
	}
	return fmt.Sprint(v)
}

func claimInt64(m map[string]any, key string) int64 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case int64:
		return n
	case int:
		return int64(n)
	default:
		return 0
	}
}

func claimStringSlice(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok || v == nil {
		return []string{"platform:user"}
	}
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return []string{"platform:user"}
		}
		return out
	case []string:
		if len(t) == 0 {
			return []string{"platform:user"}
		}
		return t
	case string:
		if t == "" {
			return []string{"platform:user"}
		}
		return []string{t}
	default:
		return []string{"platform:user"}
	}
}
