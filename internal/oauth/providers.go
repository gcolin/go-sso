package oauth

import (
	"strings"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/model"
)

// IdentityProviderRegistry lists enabled external IdPs from config.federation.
type IdentityProviderRegistry struct {
	cfg *config.AppConfig
}

func NewIdentityProviderRegistry(cfg *config.AppConfig) *IdentityProviderRegistry {
	return &IdentityProviderRegistry{cfg: cfg}
}

func (r *IdentityProviderRegistry) ListEnabled() []model.IdentityProvider {
	if r == nil || r.cfg == nil {
		return nil
	}
	out := make([]model.IdentityProvider, 0, len(r.cfg.Federation.IdentityProviders))
	for _, p := range r.cfg.Federation.IdentityProviders {
		if p.Enabled {
			out = append(out, p)
		}
	}
	return out
}

func (r *IdentityProviderRegistry) FindEnabledByID(providerID string) (model.IdentityProvider, bool) {
	providerID = strings.TrimSpace(providerID)
	if providerID == "" {
		return model.IdentityProvider{}, false
	}
	for _, p := range r.ListEnabled() {
		if p.ID == providerID {
			return p, true
		}
	}
	return model.IdentityProvider{}, false
}
