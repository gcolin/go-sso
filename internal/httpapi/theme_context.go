package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gcolin/go-sso/internal/themes"
)

// applyClientTheme resolves OAuth client branding + effective theme into the page model.
func (s *Server) applyClientTheme(r *http.Request, model map[string]any) {
	clientID := resolveClientID(r, model)
	if clientID == "" {
		clientID = s.rt.Sessions.CurrentClientID(r)
	}
	var clientTheme string
	if clientID != "" {
		model["clientId"] = clientID
		if c, ok := s.rt.Clients.FindByID(clientID); ok {
			model["clientDisplayName"] = c.DisplayLabel()
			clientTheme = c.Theme
		}
	}
	theme := themes.Effective(clientTheme, s.rt.Config.Server.DefaultTheme)
	if s.rt.Themes != nil && !s.rt.Themes.Exists(theme) {
		theme = themes.BaseTheme
	}
	model["theme"] = theme
	if s.rt.Themes != nil && s.rt.Themes.HasThemeCSS(theme) {
		model["themeCss"] = "/themes/" + theme + "/static/css/theme.css"
	}
	switch theme {
	case "tregor":
		model["themeColor"] = "#2d1d15"
	case "chessprogress":
		model["themeColor"] = "#0f241c"
	}
}

// rememberSessionClient stores client_id in the session JWT for later theming (e.g. /profile).
func (s *Server) rememberSessionClient(w http.ResponseWriter, r *http.Request, clientID string) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return
	}
	user := s.rt.Sessions.CurrentUser(r)
	if user == nil {
		return
	}
	if s.rt.Sessions.CurrentClientID(r) == clientID {
		return
	}
	_ = s.rt.Sessions.WriteSessionForClient(w, user, clientID)
}

func resolveClientID(r *http.Request, model map[string]any) string {
	if model != nil {
		if v, ok := model["clientId"].(string); ok {
			if id := strings.TrimSpace(v); id != "" {
				return id
			}
		}
	}
	if id := strings.TrimSpace(r.URL.Query().Get("clientId")); id != "" {
		return id
	}
	if id := strings.TrimSpace(r.URL.Query().Get("client_id")); id != "" {
		return id
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		if id := strings.TrimSpace(r.Form.Get("clientId")); id != "" {
			return id
		}
		if id := strings.TrimSpace(r.Form.Get("client_id")); id != "" {
			return id
		}
	}
	returnUrl := ""
	if model != nil {
		if v, ok := model["returnUrl"].(string); ok {
			returnUrl = v
		}
	}
	if returnUrl == "" {
		returnUrl = r.URL.Query().Get("returnUrl")
	}
	if returnUrl == "" && r.Method == http.MethodPost {
		_ = r.ParseForm()
		returnUrl = r.Form.Get("returnUrl")
	}
	return clientIDFromReturnURL(returnUrl)
}

func clientIDFromReturnURL(returnURL string) string {
	returnURL = strings.TrimSpace(returnURL)
	if returnURL == "" {
		return ""
	}
	pathPart, query, ok := strings.Cut(returnURL, "?")
	_ = pathPart
	if !ok {
		// maybe absolute URL
		if u, err := url.Parse(returnURL); err == nil {
			return strings.TrimSpace(u.Query().Get("client_id"))
		}
		return ""
	}
	vals, err := url.ParseQuery(query)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(vals.Get("client_id"))
}

func (s *Server) withThemeOptions(model map[string]any, selected string) {
	selected = strings.TrimSpace(selected)
	var options []map[string]any
	options = append(options, map[string]any{
		"id":       "",
		"label":    s.rt.Messages.Resolve(modelString(model, "lang"), "admin.clientForm.themeDefault", "Server default"),
		"selected": selected == "",
	})
	if s.rt.Themes != nil {
		for _, info := range s.rt.Themes.List() {
			options = append(options, map[string]any{
				"id":       info.ID,
				"label":    info.DisplayName,
				"selected": selected == info.ID,
			})
		}
	}
	model["themeOptions"] = options
	model["formTheme"] = selected
	model["hasThemeOptions"] = len(options) > 0
}

func modelString(model map[string]any, key string) string {
	if model == nil {
		return "fr"
	}
	if v, ok := model["lang"].(string); ok && v != "" {
		return v
	}
	return "fr"
}

func (s *Server) validateClientTheme(theme string) error {
	theme = strings.TrimSpace(theme)
	if theme == "" {
		return nil
	}
	if s.rt.Themes == nil || !s.rt.Themes.Exists(theme) {
		return &themeValidationError{msg: "unknown theme: " + theme}
	}
	return nil
}

type themeValidationError struct{ msg string }

func (e *themeValidationError) Error() string { return e.msg }
