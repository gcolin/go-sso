package httpapi

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/model"
)

func (s *Server) adminSettingsRoot(w http.ResponseWriter, r *http.Request) {
	if s.requireAdminHTML(w, r) == nil {
		return
	}
	s.redirect(w, r, "/admin/settings/server", http.StatusFound)
}

func (s *Server) settingsNavModel(active string) map[string]bool {
	return map[string]bool{
		"settingsServerActive":     active == "server",
		"settingsSecurityActive":   active == "security",
		"settingsFederationActive": active == "federation",
		"settingsMailActive":       active == "mail",
		"settingsClientsActive":    active == "clients",
	}
}

func (s *Server) withSettingsNav(model map[string]any, active string) {
	model["activePage"] = "settings"
	for k, v := range s.settingsNavModel(active) {
		model[k] = v
	}
}

func (s *Server) saveAppConfig() error {
	cfg := s.rt.Config
	cfg.Defaults()
	if err := config.Validate(cfg); err != nil {
		return err
	}
	return s.rt.Loader.Save(cfg)
}

func (s *Server) adminSettingsServerPage(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdminHTML(w, r)
	if admin == nil {
		return
	}
	cfg := s.rt.Config.Server
	model := s.pageModel(r, "page.adminSettingsServer", admin)
	model["activePage"] = "settings"
	for k, v := range s.settingsNavModel("server") {
		model[k] = v
	}
	model["formHost"] = cfg.Host
	model["formPort"] = cfg.Port
	model["formPublicBaseUrl"] = cfg.PublicBaseURL
	model["formTitle"] = cfg.Title
	model["formRealm"] = cfg.Realm
	model["formDefaultLocale"] = cfg.DefaultLocale
	s.applyFlash(r, model)
	s.render(w, http.StatusOK, "admin/settingsServer", model)
}

func (s *Server) adminSettingsServerUpdate(w http.ResponseWriter, r *http.Request) {
	if s.requireAdminHTML(w, r) == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	port, err := strconv.Atoi(strings.TrimSpace(r.Form.Get("port")))
	if err != nil || port <= 0 || port > 65535 {
		s.redirect(w, r, "/admin/settings/server?errorKey="+url.QueryEscape("error.settings.portInvalid"), http.StatusFound)
		return
	}
	prev := s.rt.Config.Server
	s.rt.Config.Server.Host = strings.TrimSpace(r.Form.Get("host"))
	s.rt.Config.Server.Port = port
	s.rt.Config.Server.PublicBaseURL = strings.TrimSpace(r.Form.Get("publicBaseUrl"))
	s.rt.Config.Server.Title = strings.TrimSpace(r.Form.Get("title"))
	s.rt.Config.Server.Realm = strings.TrimSpace(r.Form.Get("realm"))
	s.rt.Config.Server.DefaultLocale = strings.TrimSpace(r.Form.Get("defaultLocale"))
	if err := s.saveAppConfig(); err != nil {
		s.rt.Config.Server = prev
		s.redirect(w, r, "/admin/settings/server?errorKey="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	s.redirect(w, r, "/admin/settings/server?messageKey=flash.settings.saved", http.StatusFound)
}

func (s *Server) adminSettingsSecurityPage(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdminHTML(w, r)
	if admin == nil {
		return
	}
	cfg := s.rt.Config.Security
	model := s.pageModel(r, "page.adminSettingsSecurity", admin)
	model["activePage"] = "settings"
	for k, v := range s.settingsNavModel("security") {
		model[k] = v
	}
	model["formSessionCookieName"] = cfg.SessionCookieName
	model["formSessionCookieSecure"] = cfg.SessionCookieSecure
	model["formSessionTtlMinutes"] = cfg.SessionTtlMinutes
	model["formLoginRateLimitMaxAttempts"] = cfg.LoginRateLimitMaxAttempts
	model["formLoginRateLimitWindowSeconds"] = cfg.LoginRateLimitWindowSeconds
	model["formEmailVerificationTtlHours"] = cfg.EmailVerificationTtlHours
	model["formDefaultUserMaxStorageBytes"] = cfg.DefaultUserMaxStorageBytes
	model["formPublicRegistrationEnabled"] = cfg.PublicRegistrationEnabled
	model["mailEnabled"] = s.rt.Config.Mail.Enabled
	s.applyFlash(r, model)
	s.render(w, http.StatusOK, "admin/settingsSecurity", model)
}

func (s *Server) adminSettingsSecurityUpdate(w http.ResponseWriter, r *http.Request) {
	if s.requireAdminHTML(w, r) == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	prev := s.rt.Config.Security
	ttl, err1 := strconv.ParseInt(strings.TrimSpace(r.Form.Get("sessionTtlMinutes")), 10, 64)
	maxAttempts, err2 := strconv.Atoi(strings.TrimSpace(r.Form.Get("loginRateLimitMaxAttempts")))
	window, err3 := strconv.ParseInt(strings.TrimSpace(r.Form.Get("loginRateLimitWindowSeconds")), 10, 64)
	verifyTTL, err4 := strconv.ParseInt(strings.TrimSpace(r.Form.Get("emailVerificationTtlHours")), 10, 64)
	storage, err5 := strconv.ParseInt(strings.TrimSpace(r.Form.Get("defaultUserMaxStorageBytes")), 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
		s.redirect(w, r, "/admin/settings/security?errorKey="+url.QueryEscape("error.settings.numberInvalid"), http.StatusFound)
		return
	}
	s.rt.Config.Security.SessionCookieName = strings.TrimSpace(r.Form.Get("sessionCookieName"))
	s.rt.Config.Security.SessionCookieSecure = r.Form.Get("sessionCookieSecure") == "true"
	s.rt.Config.Security.SessionTtlMinutes = ttl
	s.rt.Config.Security.LoginRateLimitMaxAttempts = maxAttempts
	s.rt.Config.Security.LoginRateLimitWindowSeconds = window
	s.rt.Config.Security.EmailVerificationTtlHours = verifyTTL
	s.rt.Config.Security.DefaultUserMaxStorageBytes = storage
	wantReg := r.Form.Get("publicRegistrationEnabled") == "true"
	if wantReg && !s.rt.Config.Mail.Enabled {
		s.redirect(w, r, "/admin/settings/security?errorKey="+url.QueryEscape("error.register.mailRequired"), http.StatusFound)
		return
	}
	s.rt.Config.Security.PublicRegistrationEnabled = wantReg
	if err := s.saveAppConfig(); err != nil {
		s.rt.Config.Security = prev
		s.redirect(w, r, "/admin/settings/security?errorKey="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	s.redirect(w, r, "/admin/settings/security?messageKey=flash.settings.saved", http.StatusFound)
}

func (s *Server) adminSettingsFederationPage(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdminHTML(w, r)
	if admin == nil {
		return
	}
	cfg := s.rt.Config.Federation
	page := s.pageModel(r, "page.adminSettingsFederation", admin)
	page["activePage"] = "settings"
	for k, v := range s.settingsNavModel("federation") {
		page[k] = v
	}
	page["formAutoProvision"] = cfg.AutoProvision
	page["formDefaultUserType"] = cfg.DefaultUserType
	page["typeUserSelected"] = cfg.DefaultUserType == "" || cfg.DefaultUserType == model.TypeUser
	page["typeAdminSelected"] = cfg.DefaultUserType == model.TypeAdmin
	page["providers"] = s.federationProviderRows(r, cfg.IdentityProviders)
	page["hasProviders"] = len(cfg.IdentityProviders) > 0
	s.applyFlash(r, page)
	s.render(w, http.StatusOK, "admin/settingsFederation", page)
}

func (s *Server) federationProviderRows(r *http.Request, providers []model.IdentityProvider) []map[string]any {
	out := make([]map[string]any, 0, len(providers))
	lang := s.lang(r)
	for _, p := range providers {
		display := strings.TrimSpace(p.DisplayName)
		if display == "" {
			display = p.ID
		}
		confirm := s.rt.Messages.Get(lang, "admin.settings.federation.confirmDelete", display)
		out = append(out, map[string]any{
			"id":               p.ID,
			"displayName":      display,
			"enabled":          p.Enabled,
			"clientId":         p.ClientID,
			"authorizationUrl": p.AuthorizationURL,
			"idEncoded":        url.QueryEscape(p.ID),
			"confirmDelete":    confirm,
		})
	}
	return out
}

func identityProviderFromForm(form url.Values) model.IdentityProvider {
	return model.IdentityProvider{
		ID:               strings.TrimSpace(form.Get("id")),
		Enabled:          form.Get("enabled") == "true",
		DisplayName:      strings.TrimSpace(form.Get("displayName")),
		Logo:             strings.TrimSpace(form.Get("logo")),
		ClientID:         strings.TrimSpace(form.Get("clientId")),
		ClientSecret:     form.Get("clientSecret"),
		AuthorizationURL: strings.TrimSpace(form.Get("authorizationUrl")),
		TokenURL:         strings.TrimSpace(form.Get("tokenUrl")),
		UserInfoURL:      strings.TrimSpace(form.Get("userInfoUrl")),
		Scopes:           strings.TrimSpace(form.Get("scopes")),
		EmailClaim:       strings.TrimSpace(form.Get("emailClaim")),
		NameClaim:        strings.TrimSpace(form.Get("nameClaim")),
		SubjectClaim:     strings.TrimSpace(form.Get("subjectClaim")),
		RedirectURI:      strings.TrimSpace(form.Get("redirectUri")),
	}
}

func (s *Server) findIdentityProvider(id string) (model.IdentityProvider, int, bool) {
	for i, p := range s.rt.Config.Federation.IdentityProviders {
		if p.ID == id {
			return p, i, true
		}
	}
	return model.IdentityProvider{}, -1, false
}

func (s *Server) providerEditModel(r *http.Request, admin *model.User, p model.IdentityProvider) map[string]any {
	page := s.pageModel(r, "page.adminSettingsFederationEdit", admin)
	s.withSettingsNav(page, "federation")
	page["formId"] = p.ID
	page["formEnabled"] = p.Enabled
	page["formDisplayName"] = p.DisplayName
	page["formLogo"] = p.Logo
	page["formClientId"] = p.ClientID
	page["formAuthorizationUrl"] = p.AuthorizationURL
	page["formTokenUrl"] = p.TokenURL
	page["formUserInfoUrl"] = p.UserInfoURL
	page["formScopes"] = p.Scopes
	page["formEmailClaim"] = p.EmailClaim
	page["formNameClaim"] = p.NameClaim
	page["formSubjectClaim"] = p.SubjectClaim
	page["formRedirectUri"] = p.RedirectURI
	page["hasClientSecret"] = strings.TrimSpace(p.ClientSecret) != ""
	return page
}

func (s *Server) adminSettingsFederationUpdate(w http.ResponseWriter, r *http.Request) {
	if s.requireAdminHTML(w, r) == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	prev := s.rt.Config.Federation
	typ := strings.TrimSpace(r.Form.Get("defaultUserType"))
	if typ == "" {
		typ = model.TypeUser
	}
	s.rt.Config.Federation.AutoProvision = r.Form.Get("autoProvision") == "true"
	s.rt.Config.Federation.DefaultUserType = typ
	if err := s.saveAppConfig(); err != nil {
		s.rt.Config.Federation = prev
		s.redirect(w, r, "/admin/settings/federation?errorKey="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	s.redirect(w, r, "/admin/settings/federation?messageKey=flash.settings.saved", http.StatusFound)
}

func (s *Server) adminSettingsFederationProviderCreate(w http.ResponseWriter, r *http.Request) {
	if s.requireAdminHTML(w, r) == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	prev := append([]model.IdentityProvider(nil), s.rt.Config.Federation.IdentityProviders...)
	p := identityProviderFromForm(r.Form)
	p.ClientSecret = strings.TrimSpace(p.ClientSecret)
	if p.ID == "" {
		s.redirect(w, r, "/admin/settings/federation?errorKey="+url.QueryEscape("error.settings.providerIdRequired"), http.StatusFound)
		return
	}
	for _, existing := range s.rt.Config.Federation.IdentityProviders {
		if existing.ID == p.ID {
			s.redirect(w, r, "/admin/settings/federation?errorKey="+url.QueryEscape("error.settings.providerExists"), http.StatusFound)
			return
		}
	}
	s.rt.Config.Federation.IdentityProviders = append(s.rt.Config.Federation.IdentityProviders, p)
	if err := s.saveAppConfig(); err != nil {
		s.rt.Config.Federation.IdentityProviders = prev
		s.redirect(w, r, "/admin/settings/federation?errorKey="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	s.redirect(w, r, "/admin/settings/federation?messageKey=flash.settings.providerCreated", http.StatusFound)
}

func (s *Server) adminSettingsFederationProviderEditPage(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdminHTML(w, r)
	if admin == nil {
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	p, _, ok := s.findIdentityProvider(id)
	if !ok {
		s.redirect(w, r, "/admin/settings/federation?errorKey="+url.QueryEscape("error.settings.providerNotFound"), http.StatusFound)
		return
	}
	page := s.providerEditModel(r, admin, p)
	s.applyFlash(r, page)
	s.render(w, http.StatusOK, "admin/settingsFederationEdit", page)
}

func (s *Server) adminSettingsFederationProviderUpdate(w http.ResponseWriter, r *http.Request) {
	if s.requireAdminHTML(w, r) == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	id := strings.TrimSpace(r.Form.Get("id"))
	existing, idx, ok := s.findIdentityProvider(id)
	if !ok {
		s.redirect(w, r, "/admin/settings/federation?errorKey="+url.QueryEscape("error.settings.providerNotFound"), http.StatusFound)
		return
	}
	prev := append([]model.IdentityProvider(nil), s.rt.Config.Federation.IdentityProviders...)
	updated := identityProviderFromForm(r.Form)
	updated.ID = existing.ID // id is immutable
	if strings.TrimSpace(updated.ClientSecret) == "" {
		updated.ClientSecret = existing.ClientSecret
	} else {
		updated.ClientSecret = strings.TrimSpace(updated.ClientSecret)
	}
	s.rt.Config.Federation.IdentityProviders[idx] = updated
	if err := s.saveAppConfig(); err != nil {
		s.rt.Config.Federation.IdentityProviders = prev
		s.redirect(w, r, "/admin/settings/federation/providers/edit?id="+url.QueryEscape(id)+"&errorKey="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	s.redirect(w, r, "/admin/settings/federation?messageKey=flash.settings.providerUpdated", http.StatusFound)
}

func (s *Server) adminSettingsFederationProviderDelete(w http.ResponseWriter, r *http.Request) {
	if s.requireAdminHTML(w, r) == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	id := strings.TrimSpace(r.Form.Get("id"))
	prev := append([]model.IdentityProvider(nil), s.rt.Config.Federation.IdentityProviders...)
	next := make([]model.IdentityProvider, 0, len(prev))
	found := false
	for _, p := range prev {
		if p.ID == id {
			found = true
			continue
		}
		next = append(next, p)
	}
	if !found {
		s.redirect(w, r, "/admin/settings/federation?errorKey="+url.QueryEscape("error.settings.providerNotFound"), http.StatusFound)
		return
	}
	s.rt.Config.Federation.IdentityProviders = next
	if err := s.saveAppConfig(); err != nil {
		s.rt.Config.Federation.IdentityProviders = prev
		s.redirect(w, r, "/admin/settings/federation?errorKey="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	s.redirect(w, r, "/admin/settings/federation?messageKey=flash.settings.providerDeleted", http.StatusFound)
}

func (s *Server) adminSettingsMailPage(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdminHTML(w, r)
	if admin == nil {
		return
	}
	cfg := s.rt.Config.Mail
	model := s.pageModel(r, "page.adminSettingsMail", admin)
	model["activePage"] = "settings"
	for k, v := range s.settingsNavModel("mail") {
		model[k] = v
	}
	model["formEnabled"] = cfg.Enabled
	model["formSmtpHost"] = cfg.SmtpHost
	model["formSmtpPort"] = cfg.SmtpPort
	model["formUsername"] = cfg.Username
	model["formFromAddress"] = cfg.FromAddress
	model["formFromName"] = cfg.FromName
	model["formStartTls"] = cfg.StartTLS
	model["hasPassword"] = strings.TrimSpace(cfg.Password) != ""
	s.applyFlash(r, model)
	s.render(w, http.StatusOK, "admin/settingsMail", model)
}

func (s *Server) adminSettingsMailUpdate(w http.ResponseWriter, r *http.Request) {
	if s.requireAdminHTML(w, r) == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	prev := s.rt.Config.Mail
	port, err := strconv.Atoi(strings.TrimSpace(r.Form.Get("smtpPort")))
	if err != nil || port <= 0 {
		s.redirect(w, r, "/admin/settings/mail?errorKey="+url.QueryEscape("error.settings.portInvalid"), http.StatusFound)
		return
	}
	s.rt.Config.Mail.Enabled = r.Form.Get("enabled") == "true"
	s.rt.Config.Mail.SmtpHost = strings.TrimSpace(r.Form.Get("smtpHost"))
	s.rt.Config.Mail.SmtpPort = port
	s.rt.Config.Mail.Username = strings.TrimSpace(r.Form.Get("username"))
	if pwd := r.Form.Get("password"); strings.TrimSpace(pwd) != "" {
		s.rt.Config.Mail.Password = pwd
	}
	s.rt.Config.Mail.FromAddress = strings.TrimSpace(r.Form.Get("fromAddress"))
	s.rt.Config.Mail.FromName = strings.TrimSpace(r.Form.Get("fromName"))
	s.rt.Config.Mail.StartTLS = r.Form.Get("startTls") == "true"
	prevSecurity := s.rt.Config.Security
	if !s.rt.Config.Mail.Enabled {
		s.rt.Config.Security.PublicRegistrationEnabled = false
	}
	if err := s.saveAppConfig(); err != nil {
		s.rt.Config.Mail = prev
		s.rt.Config.Security = prevSecurity
		s.redirect(w, r, "/admin/settings/mail?errorKey="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	s.redirect(w, r, "/admin/settings/mail?messageKey=flash.settings.saved", http.StatusFound)
}
