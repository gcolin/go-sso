package httpapi

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/gcolin/go-sso/internal/model"
	"github.com/gcolin/go-sso/internal/oauth"
	"github.com/gcolin/go-sso/internal/security"
	"github.com/gcolin/go-sso/internal/templates"
)

func (s *Server) basePath(_ *http.Request) string {
	return s.contextPath()
}

func (s *Server) contextPath() string {
	return s.rt.Config.Server.ContextPath()
}

func (s *Server) path(rel string) string {
	ctx := s.contextPath()
	pathPart, query := splitPathQuery(rel)
	if pathPart == "" || pathPart == "/" {
		if ctx == "" {
			pathPart = "/"
		} else {
			pathPart = ctx + "/"
		}
		return pathPart + query
	}
	if !strings.HasPrefix(pathPart, "/") {
		pathPart = "/" + pathPart
	}
	if ctx != "" && (pathPart == ctx || strings.HasPrefix(pathPart, ctx+"/")) {
		return pathPart + query
	}
	return ctx + pathPart + query
}

// relativeRequestURL is the request path (+ query) relative to the SSO context path (Java relativeUrl).
func (s *Server) relativeRequestURL(r *http.Request) string {
	ctx := s.contextPath()
	pathPart := r.URL.Path
	if ctx != "" && (pathPart == ctx || strings.HasPrefix(pathPart, ctx+"/")) {
		pathPart = pathPart[len(ctx):]
		if pathPart == "" {
			pathPart = "/"
		}
	}
	if pathPart == "" {
		pathPart = "/"
	}
	if r.URL.RawQuery != "" {
		return pathPart + "?" + r.URL.RawQuery
	}
	return pathPart
}

// appReturnURL turns a sanitized relative return URL into an absolute-path redirect target.
func (s *Server) appReturnURL(returnURL string) string {
	returnURL = strings.TrimSpace(returnURL)
	if returnURL == "" {
		return s.path("/")
	}
	if strings.HasPrefix(returnURL, "http://") || strings.HasPrefix(returnURL, "https://") {
		return returnURL
	}
	if strings.HasPrefix(returnURL, "/") {
		return s.path(returnURL)
	}
	return s.path("/")
}

func splitPathQuery(rel string) (pathPart, query string) {
	if i := strings.IndexByte(rel, '?'); i >= 0 {
		return rel[:i], rel[i:]
	}
	return rel, ""
}

func (s *Server) redirect(w http.ResponseWriter, r *http.Request, rel string, code int) {
	http.Redirect(w, r, s.path(rel), code)
}

func (s *Server) lang(r *http.Request) string {
	if l := s.rt.Config.Server.DefaultLocale; l != "" {
		return l
	}
	return "fr"
}

func (s *Server) render(w http.ResponseWriter, status int, template string, model map[string]any) {
	html, err := s.rt.Templates.Render(template, model)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(html))
}

func (s *Server) pageModel(r *http.Request, titleKey string, user *model.User) map[string]any {
	m := s.rt.Templates.BaseModel(
		titleKey,
		s.lang(r),
		s.basePath(r),
		s.rt.Config.Server.EffectiveTitle(),
		user,
	)
	sub := s.csrfSubject(r)
	if user != nil && sub == "" {
		sub = user.ID
	}
	if tok, err := s.rt.JWT.CreateCsrfToken(sub); err == nil {
		m["csrfToken"] = tok
	}
	s.applyClientTheme(r, m)
	return m
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	user := s.rt.Sessions.CurrentUser(r)
	if user != nil {
		model := s.pageModel(r, "page.home", user)
		model["activePage"] = "home"
		s.render(w, http.StatusOK, "home", model)
		return
	}
	returnURL := r.URL.Query().Get("returnUrl")
	if strings.TrimSpace(returnURL) == "" {
		returnURL = s.relativeRequestURL(r)
	} else {
		returnURL = s.rt.ExternalOAuth.SanitizeReturnURL(returnURL)
	}
	s.renderLogin(w, r, returnURL, "", r.URL.Query().Get("messageKey"), "")
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	returnURL := r.URL.Query().Get("returnUrl")
	if strings.TrimSpace(returnURL) == "" {
		returnURL = s.relativeRequestURL(r)
	} else {
		returnURL = s.rt.ExternalOAuth.SanitizeReturnURL(returnURL)
	}
	s.renderLogin(w, r, returnURL, r.URL.Query().Get("clientId"), r.URL.Query().Get("messageKey"), r.URL.Query().Get("errorKey"))
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, returnURL, clientID, messageKey, errorKey string) {
	s.renderLoginWithError(w, r, returnURL, clientID, messageKey, errorKey)
}

// renderLoginWithError renders the login page; errorKey may take MessageFormat args ({0}, …).
func (s *Server) renderLoginWithError(w http.ResponseWriter, r *http.Request, returnURL, clientID, messageKey, errorKey string, errorArgs ...any) {
	model := s.pageModel(r, "page.login", nil)
	model["returnUrl"] = returnURL
	model["returnUrlEncoded"] = url.QueryEscape(returnURL)
	if clientID != "" {
		model["clientId"] = clientID
	}
	s.applyClientTheme(r, model)
	model["publicRegistrationEnabled"] = s.publicRegistrationAllowed()
	model["identityProviders"] = s.identityProviderViews(returnURL)
	if messageKey != "" {
		model["message"] = s.rt.Messages.Resolve(s.lang(r), messageKey, messageKey)
	}
	if errorKey != "" {
		if len(errorArgs) > 0 {
			model["error"] = s.rt.Messages.Get(s.lang(r), errorKey, errorArgs...)
		} else {
			model["error"] = s.rt.Messages.Resolve(s.lang(r), errorKey, errorKey)
		}
	}
	s.render(w, http.StatusOK, "login", model)
}

func (s *Server) loginFormSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireCSRF(w, r) {
		return
	}
	email := r.Form.Get("email")
	password := r.Form.Get("password")
	returnURL := r.Form.Get("returnUrl")
	clientID := strings.TrimSpace(r.Form.Get("clientId"))
	if strings.TrimSpace(returnURL) == "" {
		returnURL = "/"
	} else {
		returnURL = s.rt.ExternalOAuth.SanitizeReturnURL(returnURL)
	}
	if clientID == "" {
		clientID = clientIDFromReturnURL(returnURL)
	}
	if retry := s.rt.RateLimit.CheckAndRecord(clientIP(r)); retry > 0 {
		s.renderLogin(w, r, returnURL, clientID, "", "error.login.rateLimited")
		return
	}
	status := s.rt.Passwords.AuthenticateStatus(email, password)
	switch status {
	case security.AuthInvalidCredentials:
		model := s.pageModel(r, "page.login", nil)
		model["returnUrl"] = returnURL
		if clientID != "" {
			model["clientId"] = clientID
		}
		s.applyClientTheme(r, model)
		model["error"] = s.rt.Messages.Resolve(s.lang(r), "error.login.invalidCredentials", "invalid credentials")
		model["publicRegistrationEnabled"] = s.publicRegistrationAllowed()
		model["identityProviders"] = s.identityProviderViews(returnURL)
		s.render(w, http.StatusUnauthorized, "login", model)
		return
	case security.AuthEmailNotVerified:
		s.redirect(w, r, "/login/unverified?email="+url.QueryEscape(strings.TrimSpace(email))+
			"&returnUrl="+url.QueryEscape(returnURL)+
			"&clientId="+url.QueryEscape(clientID), http.StatusFound)
		return
	}
	user := s.rt.Passwords.Authenticate(email, password)
	if user == nil {
		s.renderLogin(w, r, returnURL, clientID, "", "error.login.invalidCredentials")
		return
	}
	if user.IsTotpEnabled() {
		if err := s.rt.Sessions.WritePending2FACookie(w, user, returnURL); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.redirect(w, r, "/login/2fa", http.StatusFound)
		return
	}
	var err error
	if clientID != "" {
		err = s.rt.Sessions.WriteSessionForClient(w, user, clientID)
	} else {
		err = s.rt.Sessions.WriteSession(w, user)
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.appReturnURL(returnURL), http.StatusFound)
}

func (s *Server) login2faPage(w http.ResponseWriter, r *http.Request) {
	pending, ok := s.rt.Sessions.ResolvePending2FA(r)
	if !ok {
		s.renderLogin(w, r, "/", "", "", "error.login.2faExpired")
		return
	}
	s.renderLogin2fa(w, r, pending, r.URL.Query().Get("messageKey"), r.URL.Query().Get("errorKey"))
}

func (s *Server) login2faSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireCSRF(w, r) {
		return
	}
	pending, ok := s.rt.Sessions.ResolvePending2FA(r)
	if !ok {
		s.renderLogin(w, r, "/", "", "", "error.login.2faExpired")
		return
	}
	if retry := s.rt.RateLimit.CheckAndRecord("2fa:" + clientIP(r) + ":" + pending.UserID); retry > 0 {
		s.renderLogin2fa(w, r, pending, "", "error.login.2faRateLimited")
		return
	}
	code := r.Form.Get("code")
	okCode, verr := s.rt.UserReg.VerifyTotpLogin(pending.UserID, code)
	if verr != nil {
		s.renderLogin2fa(w, r, pending, "", userErrorKey(verr))
		return
	}
	if !okCode {
		s.renderLogin2fa(w, r, pending, "", "error.login.2faInvalidCode")
		return
	}
	user, found := s.rt.UserReg.FindByID(pending.UserID)
	if !found {
		s.rt.Sessions.ClearPending2FACookie(w)
		s.renderLogin(w, r, "/", "", "", "error.user.notFound")
		return
	}
	s.rt.Sessions.ClearPending2FACookie(w)
	returnURL := pending.ReturnURL
	if strings.TrimSpace(returnURL) == "" {
		returnURL = "/"
	} else {
		returnURL = s.rt.ExternalOAuth.SanitizeReturnURL(returnURL)
	}
	clientID := clientIDFromReturnURL(returnURL)
	var err error
	if clientID != "" {
		err = s.rt.Sessions.WriteSessionForClient(w, user, clientID)
	} else {
		err = s.rt.Sessions.WriteSession(w, user)
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.appReturnURL(returnURL), http.StatusFound)
}

func (s *Server) renderLogin2fa(w http.ResponseWriter, r *http.Request, pending *security.Pending2FAClaims, messageKey, errorKey string) {
	model := s.pageModel(r, "page.login2fa", nil)
	model["email"] = pending.Email
	model["returnUrl"] = pending.ReturnURL
	s.applyClientTheme(r, model)
	if messageKey != "" {
		model["message"] = s.rt.Messages.Resolve(s.lang(r), messageKey, messageKey)
	}
	if errorKey != "" {
		model["error"] = s.rt.Messages.Resolve(s.lang(r), errorKey, errorKey)
	}
	s.render(w, http.StatusOK, "login2fa", model)
}

func (s *Server) loginUnverifiedPage(w http.ResponseWriter, r *http.Request) {
	if s.rt.Sessions.CurrentUser(r) != nil {
		s.redirect(w, r, "/", http.StatusFound)
		return
	}
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	returnURL := s.sanitizeRegisterReturnURL(r.URL.Query().Get("returnUrl"))
	if email == "" {
		s.redirect(w, r, "/?returnUrl="+url.QueryEscape(returnURL), http.StatusFound)
		return
	}
	model := s.pageModel(r, "page.emailNotVerified", nil)
	model["email"] = email
	model["returnUrl"] = returnURL
	model["returnUrlEncoded"] = url.QueryEscape(returnURL)
	model["notVerifiedMessage"] = s.rt.Messages.Resolve(s.lang(r), "error.login.emailNotVerified", "email not verified")
	if mk := r.URL.Query().Get("messageKey"); mk != "" {
		model["message"] = s.rt.Messages.Resolve(s.lang(r), mk, mk)
	}
	if ek := r.URL.Query().Get("errorKey"); ek != "" {
		model["error"] = s.rt.Messages.Resolve(s.lang(r), ek, ek)
	}
	s.render(w, http.StatusOK, "emailNotVerified", model)
}


func (s *Server) logoutHTML(w http.ResponseWriter, r *http.Request) {
	if !s.requireCSRF(w, r) {
		return
	}
	s.rt.Sessions.ClearSession(w)
	s.redirect(w, r, "/", http.StatusFound)
}

// oauthLogout implements OIDC RP-Initiated Logout (GET end_session_endpoint).
// Clears the SSO session cookie then redirects to post_logout_redirect_uri when allowed.
func (s *Server) oauthLogout(w http.ResponseWriter, r *http.Request) {
	s.rt.Sessions.ClearSession(w)
	target := strings.TrimSpace(r.URL.Query().Get("post_logout_redirect_uri"))
	if target == "" {
		s.redirect(w, r, "/", http.StatusFound)
		return
	}
	if !s.allowedPostLogoutRedirect(target) {
		s.redirect(w, r, "/", http.StatusFound)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) allowedPostLogoutRedirect(target string) bool {
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	candidates := []string{s.rt.Config.Server.PublicBaseURL}
	for _, c := range s.rt.Clients.ListAll() {
		candidates = append(candidates, c.RedirectURI)
	}
	for _, c := range candidates {
		base, err := url.Parse(strings.TrimSpace(c))
		if err != nil || base.Scheme == "" || base.Host == "" {
			continue
		}
		if strings.EqualFold(base.Scheme, u.Scheme) && strings.EqualFold(base.Host, u.Host) {
			return true
		}
	}
	return false
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := oauth.AuthorizeQuery{
		ResponseType:        r.URL.Query().Get("response_type"),
		ClientID:            r.URL.Query().Get("client_id"),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		Scope:               r.URL.Query().Get("scope"),
		State:               r.URL.Query().Get("state"),
		Nonce:               r.URL.Query().Get("nonce"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
	}
	user := s.rt.Sessions.CurrentUser(r)
	if user == nil {
		// Java parity: render login in-place with current authorize URL as returnUrl.
		s.renderLogin(w, r, s.relativeRequestURL(r), q.ClientID, "", "")
		return
	}
	s.rememberSessionClient(w, r, q.ClientID)
	res := s.rt.OAuth.BeginAuthorize(q, user)
	switch res.Type {
	case oauth.AuthorizeRedirect, oauth.AuthorizeRedirectError:
		http.Redirect(w, r, res.RedirectURL, http.StatusFound)
	case oauth.AuthorizeConsent:
		page := s.pageModel(r, "page.consent", user)
		page["requestId"] = res.RequestID
		page["clientId"] = res.ClientID
		display := res.ClientDisplayName
		if display == "" {
			display = model.HumanizeClientID(res.ClientID)
		}
		page["clientDisplayName"] = display
		s.applyClientTheme(r, page)
		labels := s.consentScopeLabels(s.lang(r), res.Scope)
		page["scopeLabels"] = labels
		page["hasScopeLabels"] = len(labels) > 0
		s.render(w, http.StatusOK, "consent", page)
	default:
		http.Error(w, res.Error, http.StatusBadRequest)
	}
}

func (s *Server) consentScopeLabels(lang, scope string) []string {
	seen := map[string]struct{}{}
	var labels []string
	for _, raw := range strings.Fields(scope) {
		key := strings.ToLower(strings.TrimSpace(raw))
		if key == "" || key == "openid" {
			continue
		}
		msgKey := "consent.scope." + key
		label := s.rt.Messages.Resolve(lang, msgKey, "")
		if label == "" || label == msgKey {
			continue
		}
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		labels = append(labels, label)
	}
	return labels
}

func (s *Server) serveStatic() http.Handler {
	staticFS, err := templates.StaticFS()
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "static assets unavailable", http.StatusInternalServerError)
		})
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(staticFS)))
}

func (s *Server) serveThemeStatic(w http.ResponseWriter, r *http.Request) {
	themeID := r.PathValue("theme")
	rel := r.PathValue("path")
	if themeID == "" || strings.Contains(themeID, "..") || rel == "" || strings.Contains(rel, "..") {
		http.NotFound(w, r)
		return
	}
	if s.rt.Themes == nil {
		http.NotFound(w, r)
		return
	}
	f, err := s.rt.Themes.OpenStatic(themeID, rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || stat.IsDir() {
		http.NotFound(w, r)
		return
	}
	data, err := io.ReadAll(f)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, path.Base(rel), stat.ModTime(), bytes.NewReader(data))
}


