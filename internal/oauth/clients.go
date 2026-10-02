package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"sync"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/model"
)

type OAuthClientRegistry struct {
	cfg    *config.AppConfig
	loader *config.Loader
	mu     sync.Mutex
}

func NewOAuthClientRegistry(cfg *config.AppConfig, loader *config.Loader) *OAuthClientRegistry {
	return &OAuthClientRegistry{cfg: cfg, loader: loader}
}

func (r *OAuthClientRegistry) ListAll() []model.OAuthClient {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]model.OAuthClient, len(r.cfg.Oauth.Clients))
	copy(out, r.cfg.Oauth.Clients)
	return out
}

func (r *OAuthClientRegistry) FindByID(clientID string) (*model.OAuthClient, bool) {
	if strings.TrimSpace(clientID) == "" {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.cfg.Oauth.Clients {
		if r.cfg.Oauth.Clients[i].ClientID == clientID {
			c := r.cfg.Oauth.Clients[i]
			return &c, true
		}
	}
	return nil, false
}

func (r *OAuthClientRegistry) Create(clientID, displayName, redirectURI, theme string, confidential bool) (*model.OAuthClient, error) {
	clientID = strings.TrimSpace(clientID)
	displayName = strings.TrimSpace(displayName)
	redirectURI = strings.TrimSpace(redirectURI)
	theme = strings.TrimSpace(theme)
	if clientID == "" {
		return nil, &ClientValidationError{Msg: "clientId is required"}
	}
	if redirectURI == "" {
		return nil, &ClientValidationError{Msg: "redirectUri is required"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.cfg.Oauth.Clients {
		if c.ClientID == clientID {
			return nil, &ClientConflictError{Msg: "oauth client already exists: " + clientID}
		}
	}
	var secret string
	if confidential {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		secret = base64.RawURLEncoding.EncodeToString(b)
	}
	client := model.OAuthClient{
		ClientID:     clientID,
		DisplayName:  displayName,
		RedirectURI:  redirectURI,
		ClientSecret: secret,
		Theme:        theme,
	}
	r.cfg.Oauth.Clients = append(r.cfg.Oauth.Clients, client)
	if err := r.loader.Save(r.cfg); err != nil {
		r.cfg.Oauth.Clients = r.cfg.Oauth.Clients[:len(r.cfg.Oauth.Clients)-1]
		return nil, err
	}
	return &client, nil
}

// Update changes displayName, redirectUri, and theme for an existing client. clientId is immutable.
func (r *OAuthClientRegistry) Update(clientID, displayName, redirectURI, theme string) (*model.OAuthClient, error) {
	clientID = strings.TrimSpace(clientID)
	displayName = strings.TrimSpace(displayName)
	redirectURI = strings.TrimSpace(redirectURI)
	theme = strings.TrimSpace(theme)
	if clientID == "" {
		return nil, &ClientValidationError{Msg: "clientId is required"}
	}
	if redirectURI == "" {
		return nil, &ClientValidationError{Msg: "redirectUri is required"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := -1
	for i, c := range r.cfg.Oauth.Clients {
		if c.ClientID == clientID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, &ClientNotFoundError{Msg: "oauth client not found: " + clientID}
	}
	prev := r.cfg.Oauth.Clients[idx]
	updated := prev
	updated.DisplayName = displayName
	updated.RedirectURI = redirectURI
	updated.Theme = theme
	r.cfg.Oauth.Clients[idx] = updated
	if err := r.loader.Save(r.cfg); err != nil {
		r.cfg.Oauth.Clients[idx] = prev
		return nil, err
	}
	return &updated, nil
}

func (r *OAuthClientRegistry) Delete(clientID string) error {
	if strings.TrimSpace(clientID) == "" {
		return &ClientValidationError{Msg: "clientId is required"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cfg.Oauth.Clients) <= 1 {
		return &ClientValidationError{Msg: "cannot delete the last oauth client"}
	}
	idx := -1
	for i, c := range r.cfg.Oauth.Clients {
		if c.ClientID == clientID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return &ClientNotFoundError{Msg: "oauth client not found: " + clientID}
	}
	r.cfg.Oauth.Clients = append(r.cfg.Oauth.Clients[:idx], r.cfg.Oauth.Clients[idx+1:]...)
	return r.loader.Save(r.cfg)
}

type ClientValidationError struct{ Msg string }

func (e *ClientValidationError) Error() string { return e.Msg }

type ClientConflictError struct{ Msg string }

func (e *ClientConflictError) Error() string { return e.Msg }

type ClientNotFoundError struct{ Msg string }

func (e *ClientNotFoundError) Error() string { return e.Msg }
