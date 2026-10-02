package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/gcolin/go-sso/internal/oauth"
	"github.com/gcolin/go-sso/internal/security"
)

func (s *Server) identityProviderViews(returnURL string) []map[string]any {
	providers := s.rt.IdProviders.ListEnabled()
	out := make([]map[string]any, 0, len(providers))
	base := s.path("/")
	if base == "/" {
		base = ""
	} else {
		base = strings.TrimSuffix(base, "/")
	}
	for _, p := range providers {
		display := strings.TrimSpace(p.DisplayName)
		if display == "" {
			display = p.ID
		}
		loginPath := base + "/auth/external/" + url.PathEscape(p.ID)
		if returnURL != "" {
			loginPath += "?returnUrl=" + url.QueryEscape(returnURL)
		}
		row := map[string]any{
			"id":          p.ID,
			"displayName": display,
			"loginUrl":    loginPath,
		}
		if logo := resolveIdPLogo(p.ID, p.Logo); logo != "" {
			row["logo"] = logo
		}
		out = append(out, row)
	}
	return out
}

// resolveIdPLogo returns a Bootstrap Icons class (e.g. bi-google).
// Explicit logo wins; short names and provider ids are mapped when possible.
func resolveIdPLogo(providerID, logo string) string {
	logo = strings.TrimSpace(logo)
	if logo != "" {
		if strings.HasPrefix(logo, "bi-") {
			return logo
		}
		if mapped := knownIdPLogo(logo); mapped != "" {
			return mapped
		}
		return logo
	}
	return knownIdPLogo(providerID)
}

func knownIdPLogo(key string) string {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "google":
		return "bi-google"
	case "microsoft", "ms", "azure", "entra", "office365", "outlook":
		return "bi-microsoft"
	case "facebook", "meta":
		return "bi-facebook"
	case "github":
		return "bi-github"
	case "apple":
		return "bi-apple"
	case "yahoo":
		return "bi-globe"
	default:
		return ""
	}
}

func (s *Server) externalLogin(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("providerId")
	returnURL := r.URL.Query().Get("returnUrl")
	redirectURL, err := s.rt.ExternalOAuth.BeginLogin(providerID, returnURL)
	if err != nil {
		var oe *oauth.ExternalOAuthError
		if errors.As(err, &oe) {
			s.renderLogin(w, r, s.rt.ExternalOAuth.SanitizeReturnURL(returnURL), "", "", "error.external."+oe.Code)
			return
		}
		s.renderLogin(w, r, "/", "", "", "error.external.provider_not_found")
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) externalCallback(w http.ResponseWriter, r *http.Request) {
	s.finishExternalCallback(w, r, r.PathValue("providerId"))
}

func (s *Server) externalCallbackRealm(w http.ResponseWriter, r *http.Request) {
	realm := strings.TrimSpace(r.PathValue("realm"))
	cfgRealm := strings.TrimSpace(s.rt.Config.Server.Realm)
	if cfgRealm != "" && realm != "" && realm != cfgRealm {
		s.renderLogin(w, r, "/", "", "", "error.external.invalid_state")
		return
	}
	s.finishExternalCallback(w, r, r.PathValue("providerId"))
}

func (s *Server) finishExternalCallback(w http.ResponseWriter, r *http.Request, providerID string) {
	q := r.URL.Query()
	linkingUserID := ""
	if u := s.rt.Sessions.CurrentUser(r); u != nil {
		linkingUserID = u.ID
	}
	user, returnURL, err := s.rt.ExternalOAuth.HandleCallback(
		providerID,
		q.Get("code"),
		q.Get("state"),
		q.Get("error"),
		q.Get("error_description"),
		linkingUserID,
	)
	if err != nil {
		s.renderExternalLoginError(w, r, returnURL, err)
		return
	}
	if err := s.rt.Sessions.WriteSessionForClient(w, user, clientIDFromReturnURL(returnURL)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.appReturnURL(returnURL), http.StatusFound)
}

func (s *Server) renderExternalLoginError(w http.ResponseWriter, r *http.Request, returnURL string, err error) {
	if returnURL == "" {
		returnURL = "/"
	}
	var oe *oauth.ExternalOAuthError
	if errors.As(err, &oe) {
		s.renderLogin(w, r, returnURL, "", "", "error.external."+oe.Code)
		return
	}
	var denied *security.ExternalLoginNotAllowedError
	if errors.As(err, &denied) {
		key := "error.login.noLocalAccount"
		if denied != nil && strings.TrimSpace(denied.MessageKey) != "" {
			key = denied.MessageKey
		}
		args := make([]any, 0, len(denied.MessageArgs))
		for i, a := range denied.MessageArgs {
			if i == 0 && key == "error.external.already_linked" {
				args = append(args, s.identityProviderDisplayName(a))
				continue
			}
			args = append(args, a)
		}
		s.renderLoginWithError(w, r, returnURL, "", "", key, args...)
		return
	}
	s.renderLogin(w, r, returnURL, "", "", "error.external.invalid_callback")
}

// identityProviderDisplayName returns configured display name or the provider id.
func (s *Server) identityProviderDisplayName(providerID string) string {
	providerID = strings.TrimSpace(providerID)
	if providerID == "" {
		return providerID
	}
	if s.rt.Config != nil {
		for _, p := range s.rt.Config.Federation.IdentityProviders {
			if p.ID == providerID {
				if dn := strings.TrimSpace(p.DisplayName); dn != "" {
					return dn
				}
				return providerID
			}
		}
	}
	return providerID
}
