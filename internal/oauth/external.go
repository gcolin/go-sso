package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/model"
	"github.com/gcolin/go-sso/internal/security"
)

// ExternalOAuthService handles login via configured federation IdPs.
type ExternalOAuthService struct {
	cfg      *config.AppConfig
	providers *IdentityProviderRegistry
	states   *ExternalOAuthStateStore
	users    *security.UserRegistry
	http     *http.Client
}

func NewExternalOAuthService(
	cfg *config.AppConfig,
	providers *IdentityProviderRegistry,
	states *ExternalOAuthStateStore,
	users *security.UserRegistry,
) *ExternalOAuthService {
	return &ExternalOAuthService{
		cfg:       cfg,
		providers: providers,
		states:    states,
		users:     users,
		http:      &http.Client{Timeout: 15 * time.Second},
	}
}

type ExternalOAuthError struct {
	Code    string
	Message string
}

func (e *ExternalOAuthError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}

func (s *ExternalOAuthService) BeginLogin(providerID, returnURL string) (string, error) {
	provider, ok := s.providers.FindEnabledByID(providerID)
	if !ok {
		return "", &ExternalOAuthError{Code: "provider_not_found", Message: "Fournisseur d'identité inconnu."}
	}
	verifier := randomURLToken(32)
	challenge := ChallengeS256(verifier)
	state := s.states.Issue(providerID, verifier, s.SanitizeReturnURL(returnURL), ExternalOAuthStateTTL)
	redirectURI := s.CallbackURL(providerID)

	authURL := provider.AuthorizationURL
	sep := "?"
	if strings.Contains(authURL, "?") {
		sep = "&"
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", provider.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", effectiveScopes(provider))
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", MethodS256)
	return authURL + sep + q.Encode(), nil
}

func (s *ExternalOAuthService) HandleCallback(providerID, code, state, errCode, errDesc, linkingUserID string) (*model.User, string, error) {
	if strings.TrimSpace(errCode) != "" {
		msg := "Connexion refusée par le fournisseur externe."
		if strings.TrimSpace(errDesc) != "" {
			msg = errDesc
		}
		return nil, "/", &ExternalOAuthError{Code: "upstream_denied", Message: msg}
	}
	if strings.TrimSpace(code) == "" || strings.TrimSpace(state) == "" {
		return nil, "/", &ExternalOAuthError{Code: "invalid_callback", Message: "Réponse OAuth externe invalide."}
	}
	pending, ok := s.states.Consume(state)
	if !ok {
		return nil, "/", &ExternalOAuthError{Code: "invalid_state", Message: "Session OAuth expirée. Reconnectez-vous."}
	}
	if pending.ProviderID != providerID {
		return nil, pending.ReturnURL, &ExternalOAuthError{Code: "invalid_state", Message: "Fournisseur OAuth incohérent."}
	}
	provider, ok := s.providers.FindEnabledByID(providerID)
	if !ok {
		return nil, pending.ReturnURL, &ExternalOAuthError{Code: "provider_not_found", Message: "Fournisseur d'identité inconnu."}
	}

	accessToken, err := s.exchangeCode(provider, providerID, code, pending.CodeVerifier)
	if err != nil {
		return nil, pending.ReturnURL, err
	}
	profile, err := s.fetchUserInfo(provider, accessToken)
	if err != nil {
		return nil, pending.ReturnURL, err
	}

	externalSubject := claimString(profile, effectiveSubjectClaim(provider))
	email := claimString(profile, effectiveEmailClaim(provider))
	name := claimString(profile, effectiveNameClaim(provider))
	if externalSubject == "" {
		return nil, pending.ReturnURL, &ExternalOAuthError{Code: "missing_subject", Message: "Le fournisseur externe n'a pas renvoyé d'identifiant."}
	}
	if email == "" {
		return nil, pending.ReturnURL, &ExternalOAuthError{Code: "missing_email", Message: "Le fournisseur externe n'a pas renvoyé d'email."}
	}

	user, err := s.users.ResolveExternalLogin(providerID, externalSubject, email, name, linkingUserID)
	if err != nil {
		return nil, pending.ReturnURL, err
	}
	returnURL := pending.ReturnURL
	if returnURL == "" {
		returnURL = "/"
	}
	return user, returnURL, nil
}

func (s *ExternalOAuthService) CallbackURL(providerID string) string {
	if provider, ok := s.providers.FindEnabledByID(providerID); ok {
		if configured := strings.TrimSpace(provider.RedirectURI); configured != "" {
			return configured
		}
	}
	base := strings.TrimRight(s.cfg.Server.PublicBaseURL, "/")
	if realm := strings.TrimSpace(s.cfg.Server.Realm); realm != "" {
		return base + "/realms/" + realm + "/broker/" + providerID + "/endpoint"
	}
	return base + "/auth/callback/" + providerID
}

func (s *ExternalOAuthService) SanitizeReturnURL(returnURL string) string {
	if strings.TrimSpace(returnURL) == "" {
		return "/"
	}
	base := strings.TrimRight(s.cfg.Server.PublicBaseURL, "/")
	contextPath := s.cfg.Server.ContextPath()
	if strings.HasPrefix(returnURL, "http://") || strings.HasPrefix(returnURL, "https://") {
		if returnURL == base || strings.HasPrefix(returnURL, base+"/") {
			path := returnURL[len(base):]
			if path == "" {
				return "/"
			}
			return path
		}
		return "/"
	}
	if strings.HasPrefix(returnURL, "/") && !strings.HasPrefix(returnURL, "//") {
		if contextPath != "" && (returnURL == contextPath || strings.HasPrefix(returnURL, contextPath+"/")) {
			path := returnURL[len(contextPath):]
			if path == "" {
				return "/"
			}
			return path
		}
		return returnURL
	}
	return "/"
}

func (s *ExternalOAuthService) exchangeCode(provider model.IdentityProvider, providerID, code, codeVerifier string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", s.CallbackURL(providerID))
	form.Set("client_id", provider.ClientID)
	form.Set("client_secret", provider.ClientSecret)
	form.Set("code_verifier", codeVerifier)

	req, err := http.NewRequest(http.MethodPost, provider.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", &ExternalOAuthError{Code: "token_exchange_failed", Message: "Impossible de contacter le fournisseur OAuth externe."}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		return "", &ExternalOAuthError{Code: "token_exchange_failed", Message: "Impossible de contacter le fournisseur OAuth externe."}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &ExternalOAuthError{Code: "token_exchange_failed", Message: "Échec de l'échange de token OAuth externe."}
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", &ExternalOAuthError{Code: "token_exchange_failed", Message: "Échec de l'échange de token OAuth externe."}
	}
	token := claimString(payload, "access_token")
	if token == "" {
		return "", &ExternalOAuthError{Code: "token_exchange_failed", Message: "Token d'accès externe manquant."}
	}
	return token, nil
}

func (s *ExternalOAuthService) fetchUserInfo(provider model.IdentityProvider, accessToken string) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, provider.UserInfoURL, nil)
	if err != nil {
		return nil, &ExternalOAuthError{Code: "userinfo_failed", Message: "Impossible de contacter le fournisseur OAuth externe."}
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		return nil, &ExternalOAuthError{Code: "userinfo_failed", Message: "Impossible de contacter le fournisseur OAuth externe."}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &ExternalOAuthError{Code: "userinfo_failed", Message: "Impossible de récupérer le profil externe."}
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, &ExternalOAuthError{Code: "userinfo_failed", Message: "Impossible de récupérer le profil externe."}
	}
	return payload, nil
}

func effectiveScopes(p model.IdentityProvider) string {
	if strings.TrimSpace(p.Scopes) != "" {
		return p.Scopes
	}
	return "openid email profile"
}

func effectiveEmailClaim(p model.IdentityProvider) string {
	if strings.TrimSpace(p.EmailClaim) != "" {
		return p.EmailClaim
	}
	return "email"
}

func effectiveNameClaim(p model.IdentityProvider) string {
	if strings.TrimSpace(p.NameClaim) != "" {
		return p.NameClaim
	}
	return "name"
}

func effectiveSubjectClaim(p model.IdentityProvider) string {
	if strings.TrimSpace(p.SubjectClaim) != "" {
		return p.SubjectClaim
	}
	return "sub"
}

func claimString(obj map[string]any, key string) string {
	if obj == nil || key == "" {
		return ""
	}
	v, ok := obj[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}
