package oauth

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/model"
	"github.com/gcolin/go-sso/internal/security"
)

type OAuthService struct {
	cfg           *config.AppConfig
	clients       *OAuthClientRegistry
	users         *security.UserDirectory
	jwt           *security.JwtService
	codes         *AuthorizationCodeStore
	authRequests  *AuthorizationRequestStore
	consent       *ConsentStore
}

func NewOAuthService(
	cfg *config.AppConfig,
	clients *OAuthClientRegistry,
	users *security.UserDirectory,
	jwt *security.JwtService,
	codes *AuthorizationCodeStore,
	authRequests *AuthorizationRequestStore,
	consent *ConsentStore,
) *OAuthService {
	return &OAuthService{
		cfg: cfg, clients: clients, users: users, jwt: jwt,
		codes: codes, authRequests: authRequests, consent: consent,
	}
}

func (s *OAuthService) NormalizeScope(scope string) string {
	if strings.TrimSpace(scope) == "" {
		return "openid profile email"
	}
	return strings.Join(strings.Fields(scope), " ")
}

func (s *OAuthService) DiscoveryDocument() map[string]any {
	base := strings.TrimRight(s.cfg.Server.PublicBaseURL, "/")
	return map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/oauth/authorize",
		"token_endpoint":                        base + "/oauth/token",
		"userinfo_endpoint":                     base + "/oauth/userinfo",
		"end_session_endpoint":                  base + "/oauth/logout",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code", "token"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"claims_supported":                      []string{"sub", "email", "email_verified", "name", "preferred_username", "roles"},
	}
}

func (s *OAuthService) JWKSDocument() map[string]any {
	return s.jwt.JWKSDocument()
}

type AuthorizeQuery struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

type AuthorizeResultType string

const (
	AuthorizeRedirect      AuthorizeResultType = "redirect"
	AuthorizeConsent       AuthorizeResultType = "consent"
	AuthorizeRedirectError AuthorizeResultType = "redirect_error"
	AuthorizeServerError   AuthorizeResultType = "server_error"
)

type AuthorizeResult struct {
	Type             AuthorizeResultType
	RedirectURL      string
	RequestID        string
	ClientID         string
	ClientDisplayName string
	RedirectURI      string
	Scope            string
	User             *model.User
	Error            string
	State            string
}

func (s *OAuthService) BeginAuthorize(query AuthorizeQuery, user *model.User) AuthorizeResult {
	client, ok := s.clients.FindByID(query.ClientID)
	if !ok {
		return AuthorizeResult{Type: AuthorizeServerError, Error: "unauthorized_client"}
	}
	if query.RedirectURI == "" || client.RedirectURI != query.RedirectURI {
		return AuthorizeResult{Type: AuthorizeServerError, Error: "invalid_request"}
	}
	if query.ResponseType != "code" && query.ResponseType != "token" {
		return AuthorizeResult{
			Type:        AuthorizeRedirectError,
			RedirectURL: BuildRedirectError(client.RedirectURI, "unsupported_response_type", query.State, query.ResponseType == "token"),
			Error:       "unsupported_response_type",
			State:       query.State,
		}
	}
	if query.ResponseType == "code" {
		method := query.CodeChallengeMethod
		if method == "" {
			method = MethodS256
		}
		if method != MethodS256 {
			return AuthorizeResult{
				Type:        AuthorizeRedirectError,
				RedirectURL: BuildRedirectError(client.RedirectURI, "invalid_request", query.State, false),
				Error:       "invalid_request",
				State:       query.State,
			}
		}
	}
	scope := s.NormalizeScope(query.Scope)
	if s.consent.HasConsent(user.ID, client.ClientID, scope) {
		return s.completeAuthorize(client, user, query, scope)
	}
	s.authRequests.PurgeExpired()
	method := query.CodeChallengeMethod
	if method == "" {
		method = MethodS256
	}
	req := s.authRequests.Create(
		user.ID, client.ClientID, query.RedirectURI, scope, query.State, query.Nonce,
		query.ResponseType, query.CodeChallenge, method,
		s.cfg.Oauth.EffectiveAuthCodeTTL(),
	)
	return AuthorizeResult{
		Type:              AuthorizeConsent,
		RequestID:         req.RequestID,
		ClientID:          client.ClientID,
		ClientDisplayName: client.DisplayLabel(),
		RedirectURI:       query.RedirectURI,
		Scope:             scope,
		User:              user,
	}
}

type DecisionResult struct {
	OK          bool
	RedirectURL string
	Message     string
}

func (s *OAuthService) HandleDecision(requestID string, allow bool) DecisionResult {
	s.authRequests.PurgeExpired()
	req, ok := s.authRequests.Consume(requestID)
	if !ok {
		return DecisionResult{Message: "error.oauth.requestExpired"}
	}
	user, ok := s.users.FindByID(req.UserID)
	if !ok {
		return DecisionResult{Message: "error.user.notFound"}
	}
	useFragment := req.ResponseType == "token"
	if !allow {
		return DecisionResult{OK: true, RedirectURL: BuildRedirectError(req.RedirectURI, "access_denied", req.State, useFragment)}
	}
	s.consent.Remember(req.UserID, req.ClientID, req.Scope)
	client, ok := s.clients.FindByID(req.ClientID)
	if !ok {
		return DecisionResult{Message: "unauthorized_client"}
	}
	query := AuthorizeQuery{
		ResponseType:        req.ResponseType,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}
	result := s.completeAuthorize(client, user, query, req.Scope)
	return DecisionResult{OK: true, RedirectURL: result.RedirectURL}
}

type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	CodeVerifier string
	ClientSecret string
	Scope        string
}

type TokenResult struct {
	OK          bool
	Error       string
	AccessToken string
	IDToken     string
	TokenType   string
	ExpiresIn   int64
	Scope       string
}

func (s *OAuthService) ExchangeToken(req TokenRequest) TokenResult {
	if req.GrantType == "client_credentials" {
		return s.exchangeClientCredentials(req)
	}
	if req.GrantType != "authorization_code" {
		return TokenResult{Error: "unsupported_grant_type"}
	}
	client, ok := s.clients.FindByID(req.ClientID)
	if !ok {
		return TokenResult{Error: "invalid_client"}
	}
	if !validateClientSecret(client, req.ClientSecret) {
		return TokenResult{Error: "invalid_client"}
	}
	s.codes.PurgeExpired()
	code, ok := s.codes.Consume(req.Code)
	if !ok {
		return TokenResult{Error: "invalid_grant"}
	}
	if client.ClientID != code.ClientID {
		return TokenResult{Error: "invalid_grant"}
	}
	redirectURI := resolveRedirectURI(req.RedirectURI, client, code)
	if code.RedirectURI != redirectURI {
		return TokenResult{Error: "invalid_grant"}
	}
	if IsChallengeRequired(code.CodeChallenge) {
		if code.CodeChallengeMethod != MethodS256 || !VerifyS256(req.CodeVerifier, code.CodeChallenge) {
			return TokenResult{Error: "invalid_grant"}
		}
	}
	user, ok := s.users.FindByID(code.UserID)
	if !ok {
		return TokenResult{Error: "invalid_grant"}
	}
	token, err := s.jwt.CreateAccessToken(user.ID, user.Email, user.Name, code.Scope, user.PlatformRoles())
	if err != nil {
		return TokenResult{Error: "server_error"}
	}
	result := TokenResult{
		OK:          true,
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   s.cfg.Oauth.EffectiveAccessTokenTTL(),
		Scope:       code.Scope,
	}
	if scopeContains(code.Scope, "openid") {
		idToken, err := s.jwt.CreateIDToken(
			user.ID, user.Email, user.Name, client.ClientID, code.Scope, code.Nonce, user.IsEmailVerified(),
		)
		if err != nil {
			return TokenResult{Error: "server_error"}
		}
		result.IDToken = idToken
	}
	return result
}

func (s *OAuthService) exchangeClientCredentials(req TokenRequest) TokenResult {
	if strings.TrimSpace(req.ClientID) == "" {
		return TokenResult{Error: "invalid_client"}
	}
	client, ok := s.clients.FindByID(req.ClientID)
	if !ok {
		return TokenResult{Error: "invalid_client"}
	}
	if !client.IsConfidential() {
		return TokenResult{Error: "unauthorized_client"}
	}
	if !validateClientSecret(client, req.ClientSecret) {
		return TokenResult{Error: "invalid_client"}
	}
	scope := ""
	if req.Scope != "" {
		scope = strings.Join(strings.Fields(req.Scope), " ")
	}
	token, err := s.jwt.CreateClientCredentialsAccessToken(client.ClientID, scope)
	if err != nil {
		return TokenResult{Error: "server_error"}
	}
	return TokenResult{
		OK: true, AccessToken: token, TokenType: "Bearer",
		ExpiresIn: s.cfg.Oauth.EffectiveAccessTokenTTL(), Scope: scope,
	}
}

type UserInfo struct {
	Sub               string   `json:"sub"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Roles             []string `json:"roles"`
	MaxStorageBytes   int64    `json:"max_storage_bytes"`
}

func (s *OAuthService) UserInfo(bearerToken string) (*UserInfo, bool) {
	if strings.TrimSpace(bearerToken) == "" {
		return nil, false
	}
	token := strings.TrimSpace(bearerToken)
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	claims, err := s.jwt.ParseAccessToken(token)
	if err != nil {
		return nil, false
	}
	user, ok := s.users.FindByID(claims.UserID)
	if !ok {
		return nil, false
	}
	return &UserInfo{
		Sub:               user.ID,
		Email:             user.Email,
		Name:              user.Name,
		PreferredUsername: user.Email,
		Roles:             user.PlatformRoles(),
		MaxStorageBytes:   user.EffectiveMaxStorageBytes(s.cfg.Security.DefaultUserMaxStorageBytes),
	}, true
}

func (s *OAuthService) completeAuthorize(client *model.OAuthClient, user *model.User, query AuthorizeQuery, scope string) AuthorizeResult {
	if query.ResponseType == "token" {
		token, err := s.jwt.CreateAccessToken(user.ID, user.Email, user.Name, scope, user.PlatformRoles())
		if err != nil {
			return AuthorizeResult{Type: AuthorizeServerError, Error: "server_error"}
		}
		return AuthorizeResult{
			Type:        AuthorizeRedirect,
			RedirectURL: BuildRedirectWithToken(query.RedirectURI, token, s.cfg.Oauth.EffectiveAccessTokenTTL(), query.State),
		}
	}
	method := query.CodeChallengeMethod
	if method == "" {
		method = MethodS256
	}
	s.codes.PurgeExpired()
	issued := s.codes.Issue(client.ClientID, user.ID, query.RedirectURI, query.CodeChallenge, method, scope, query.Nonce, s.cfg.Oauth.EffectiveAuthCodeTTL())
	return AuthorizeResult{
		Type:        AuthorizeRedirect,
		RedirectURL: BuildRedirectWithCode(query.RedirectURI, issued.RawCode, query.State),
	}
}

func scopeContains(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

func validateClientSecret(client *model.OAuthClient, provided string) bool {
	if client.ClientSecret == "" {
		return true
	}
	return client.ClientSecret == provided
}

func resolveRedirectURI(requested string, client *model.OAuthClient, code model.AuthorizationCode) string {
	if strings.TrimSpace(requested) != "" {
		return strings.TrimSpace(requested)
	}
	if client.RedirectURI == code.RedirectURI {
		return client.RedirectURI
	}
	return requested
}

func BuildRedirectWithCode(redirectURI, code, state string) string {
	return buildRedirectQuery(redirectURI, "code="+url.QueryEscape(code), state)
}

func BuildRedirectWithToken(redirectURI, accessToken string, expiresIn int64, state string) string {
	params := fmt.Sprintf("access_token=%s&token_type=Bearer&expires_in=%d", url.QueryEscape(accessToken), expiresIn)
	return buildRedirectFragment(redirectURI, params, state)
}

func BuildRedirectError(redirectURI, errorCode, state string, useFragment bool) string {
	params := "error=" + url.QueryEscape(errorCode)
	if strings.TrimSpace(state) != "" {
		params += "&state=" + url.QueryEscape(state)
	}
	if useFragment {
		return buildRedirectFragment(redirectURI, params, "")
	}
	return buildRedirectQuery(redirectURI, params, "")
}

func buildRedirectQuery(redirectURI, params, state string) string {
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	out := redirectURI + sep + params
	if strings.TrimSpace(state) != "" {
		out += "&state=" + url.QueryEscape(state)
	}
	return out
}

func buildRedirectFragment(redirectURI, params, state string) string {
	sep := "#"
	if strings.Contains(redirectURI, "#") {
		sep = "&"
	}
	out := redirectURI + sep + params
	if strings.TrimSpace(state) != "" {
		out += "&state=" + url.QueryEscape(state)
	}
	return out
}
