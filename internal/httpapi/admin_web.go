package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gcolin/go-sso/internal/model"
)

func (s *Server) requireAdminHTML(w http.ResponseWriter, r *http.Request) *model.User {
	user := s.rt.Sessions.CurrentUser(r)
	if user == nil {
		ret := s.path(r.URL.Path)
		if r.URL.RawQuery != "" {
			ret += "?" + r.URL.RawQuery
		}
		s.redirect(w, r, "/login?returnUrl="+url.QueryEscape(ret), http.StatusFound)
		return nil
	}
	if !user.IsAdmin() {
		msg := s.rt.Messages.Resolve(s.lang(r), "error.adminOnly", "admin required")
		model := s.pageModel(r, "page.error", user)
		model["message"] = msg
		model["error"] = msg
		s.render(w, http.StatusForbidden, "error", model)
		return nil
	}
	return user
}

func (s *Server) applyFlash(r *http.Request, model map[string]any) {
	lang := s.lang(r)
	if mk := r.URL.Query().Get("messageKey"); mk != "" {
		model["message"] = s.rt.Messages.Resolve(lang, mk, mk)
	}
	if ek := r.URL.Query().Get("errorKey"); ek != "" {
		model["error"] = s.rt.Messages.Resolve(lang, ek, ek)
	}
}

func (s *Server) adminRoot(w http.ResponseWriter, r *http.Request) {
	s.redirect(w, r, "/admin/settings", http.StatusFound)
}

func (s *Server) adminClientsPage(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdminHTML(w, r)
	if admin == nil {
		return
	}
	model := s.pageModel(r, "page.adminClients", admin)
	s.withSettingsNav(model, "clients")
	model["clients"] = s.rt.Clients.ListAll()
	s.applyFlash(r, model)
	s.render(w, http.StatusOK, "admin/clients", model)
}

func (s *Server) adminClientFormPage(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdminHTML(w, r)
	if admin == nil {
		return
	}
	model := s.pageModel(r, "page.adminClientNew", admin)
	s.withSettingsNav(model, "clients")
	s.withThemeOptions(model, "")
	s.render(w, http.StatusOK, "admin/clientForm", model)
}

func (s *Server) adminClientCreatePage(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdminHTML(w, r)
	if admin == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	clientID := r.Form.Get("clientId")
	displayName := r.Form.Get("displayName")
	redirectURI := r.Form.Get("redirectUri")
	theme := strings.TrimSpace(r.Form.Get("theme"))
	confidential := r.Form.Get("confidential") == "true"
	if err := s.validateClientTheme(theme); err != nil {
		model := s.pageModel(r, "page.adminClientNew", admin)
		s.withSettingsNav(model, "clients")
		model["error"] = err.Error()
		model["formClientId"] = clientID
		model["formDisplayName"] = displayName
		model["formRedirectUri"] = redirectURI
		model["formConfidential"] = confidential
		s.withThemeOptions(model, theme)
		s.render(w, http.StatusBadRequest, "admin/clientForm", model)
		return
	}
	client, err := s.rt.Clients.Create(clientID, displayName, redirectURI, theme, confidential)
	if err != nil {
		model := s.pageModel(r, "page.adminClientNew", admin)
		s.withSettingsNav(model, "clients")
		model["error"] = err.Error()
		model["formClientId"] = clientID
		model["formDisplayName"] = displayName
		model["formRedirectUri"] = redirectURI
		model["formConfidential"] = confidential
		s.withThemeOptions(model, theme)
		s.render(w, http.StatusBadRequest, "admin/clientForm", model)
		return
	}
	model := s.pageModel(r, "page.adminClientCreated", admin)
	s.withSettingsNav(model, "clients")
	model["client"] = client
	s.render(w, http.StatusOK, "admin/clientCreated", model)
}

func (s *Server) adminClientEditPage(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdminHTML(w, r)
	if admin == nil {
		return
	}
	clientID := r.PathValue("clientId")
	client, ok := s.rt.Clients.FindByID(clientID)
	if !ok {
		s.redirect(w, r, "/admin/clients?errorKey="+url.QueryEscape("oauth client not found"), http.StatusFound)
		return
	}
	model := s.pageModel(r, "page.adminClientEdit", admin)
	s.withSettingsNav(model, "clients")
	model["editingClient"] = true
	model["formClientId"] = client.ClientID
	model["formDisplayName"] = client.DisplayName
	model["formRedirectUri"] = client.RedirectURI
	model["formConfidential"] = client.IsConfidential()
	model["formAction"] = s.basePath(r) + "/admin/clients/" + url.PathEscape(client.ClientID)
	s.withThemeOptions(model, client.Theme)
	s.render(w, http.StatusOK, "admin/clientForm", model)
}

func (s *Server) adminClientUpdatePage(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdminHTML(w, r)
	if admin == nil {
		return
	}
	clientID := r.PathValue("clientId")
	if !s.requireCSRF(w, r) {
		return
	}
	displayName := r.Form.Get("displayName")
	redirectURI := r.Form.Get("redirectUri")
	theme := strings.TrimSpace(r.Form.Get("theme"))
	if err := s.validateClientTheme(theme); err != nil {
		model := s.pageModel(r, "page.adminClientEdit", admin)
		s.withSettingsNav(model, "clients")
		model["error"] = err.Error()
		model["editingClient"] = true
		model["formClientId"] = clientID
		model["formDisplayName"] = displayName
		model["formRedirectUri"] = redirectURI
		model["formAction"] = s.basePath(r) + "/admin/clients/" + url.PathEscape(clientID)
		s.withThemeOptions(model, theme)
		s.render(w, http.StatusBadRequest, "admin/clientForm", model)
		return
	}
	if _, err := s.rt.Clients.Update(clientID, displayName, redirectURI, theme); err != nil {
		model := s.pageModel(r, "page.adminClientEdit", admin)
		s.withSettingsNav(model, "clients")
		model["error"] = err.Error()
		model["editingClient"] = true
		model["formClientId"] = clientID
		model["formDisplayName"] = displayName
		model["formRedirectUri"] = redirectURI
		model["formAction"] = s.basePath(r) + "/admin/clients/" + url.PathEscape(clientID)
		s.withThemeOptions(model, theme)
		s.render(w, http.StatusBadRequest, "admin/clientForm", model)
		return
	}
	s.redirect(w, r, "/admin/clients?messageKey=flash.client.updated", http.StatusFound)
}

func (s *Server) adminClientDeletePage(w http.ResponseWriter, r *http.Request) {
	if s.requireAdminHTML(w, r) == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	if err := s.rt.Clients.Delete(r.Form.Get("clientId")); err != nil {
		s.redirect(w, r, "/admin/clients?errorKey="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	s.redirect(w, r, "/admin/clients?messageKey=flash.client.deleted", http.StatusFound)
}

func (s *Server) adminUsersPage(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdminHTML(w, r)
	if admin == nil {
		return
	}
	model := s.pageModel(r, "page.adminUsers", admin)
	model["activePage"] = "users"
	model["users"] = s.rt.UserReg.ListAll()
	s.applyFlash(r, model)
	s.render(w, http.StatusOK, "admin/users", model)
}

func (s *Server) adminUserFormPage(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdminHTML(w, r)
	if admin == nil {
		return
	}
	model := s.pageModel(r, "page.adminUserNew", admin)
	model["activePage"] = "users-new"
	model["formAction"] = "/admin/users"
	s.render(w, http.StatusOK, "admin/userForm", model)
}

func (s *Server) adminUserEditPage(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdminHTML(w, r)
	if admin == nil {
		return
	}
	userID := r.URL.Query().Get("userId")
	edit, ok := s.rt.UserReg.FindByID(userID)
	if !ok {
		s.redirect(w, r, "/admin/users?errorKey=error.user.notFound", http.StatusFound)
		return
	}
	model := s.pageModel(r, "page.adminUserEdit", admin)
	model["activePage"] = "users"
	model["editUser"] = edit
	model["formAction"] = "/admin/users/update"
	model["formEmail"] = edit.Email
	model["formName"] = edit.Name
	model["formType"] = edit.AccountType()
	model["formEmailVerified"] = edit.IsEmailVerified()
	model["totpEnabled"] = edit.IsTotpEnabled()
	s.applyFlash(r, model)
	s.render(w, http.StatusOK, "admin/userForm", model)
}

func (s *Server) adminUserCreatePage(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdminHTML(w, r)
	if admin == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	email := r.Form.Get("email")
	name := r.Form.Get("name")
	typ := r.Form.Get("type")
	password := r.Form.Get("password")
	user, err := s.rt.UserReg.Create(email, name, typ, password, 0)
	if err != nil {
		model := s.pageModel(r, "page.adminUserNew", admin)
		model["activePage"] = "users-new"
		model["formAction"] = "/admin/users"
		model["error"] = err.Error()
		model["formEmail"] = email
		model["formName"] = name
		model["formType"] = typ
		s.render(w, http.StatusBadRequest, "admin/userForm", model)
		return
	}
	messageKey := "flash.user.created"
	if s.rt.AccountVerify.IsEnabled() && user != nil && !user.IsEmailVerified() {
		if err := s.rt.AccountVerify.SendVerificationEmail(user, s.lang(r)); err != nil {
			http.Redirect(w, r, s.path("/admin/users?errorKey="+url.QueryEscape("error.mail.sendFailed")), http.StatusFound)
			return
		}
		messageKey = "flash.user.verificationEmailSent"
	}
	http.Redirect(w, r, s.path("/admin/users?messageKey="+messageKey), http.StatusFound)
}

func (s *Server) adminUserUpdatePage(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdminHTML(w, r)
	if admin == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	userID := r.Form.Get("userId")
	email := r.Form.Get("email")
	name := r.Form.Get("name")
	typ := r.Form.Get("type")
	password := r.Form.Get("password")
	var emailVerified *bool
	if r.Form.Has("emailVerified") {
		v := r.Form.Get("emailVerified") == "true" || r.Form.Get("emailVerified") == "on"
		emailVerified = &v
	}
	_, err := s.rt.UserReg.Update(userID, email, name, typ, password, emailVerified, nil)
	if err != nil {
		edit, _ := s.rt.UserReg.FindByID(userID)
		model := s.pageModel(r, "page.adminUserEdit", admin)
		model["activePage"] = "users"
		model["formAction"] = "/admin/users/update"
		model["error"] = err.Error()
		if edit != nil {
			model["editUser"] = edit
		}
		model["formEmail"] = email
		model["formName"] = name
		model["formType"] = typ
		s.render(w, http.StatusBadRequest, "admin/userForm", model)
		return
	}
	http.Redirect(w, r, s.path("/admin/users?messageKey=flash.user.updated"), http.StatusFound)
}

func (s *Server) adminUserDeletePage(w http.ResponseWriter, r *http.Request) {
	if s.requireAdminHTML(w, r) == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	if err := s.rt.UserReg.Delete(r.Form.Get("userId")); err != nil {
		http.Redirect(w, r, s.path("/admin/users?errorKey="+url.QueryEscape(err.Error())), http.StatusFound)
		return
	}
	http.Redirect(w, r, s.path("/admin/users?messageKey=flash.user.deleted"), http.StatusFound)
}

func (s *Server) adminUserDisable2faPage(w http.ResponseWriter, r *http.Request) {
	if s.requireAdminHTML(w, r) == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	if err := s.rt.UserReg.DisableTotp(r.Form.Get("userId")); err != nil {
		http.Redirect(w, r, s.path("/admin/users?errorKey="+url.QueryEscape(err.Error())), http.StatusFound)
		return
	}
	http.Redirect(w, r, s.path("/admin/users?messageKey=flash.user.2faRemoved"), http.StatusFound)
}
