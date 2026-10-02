package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gcolin/go-sso/internal/model"
	"github.com/gcolin/go-sso/internal/security"
)

func (s *Server) requireUserHTML(w http.ResponseWriter, r *http.Request) *model.User {
	user := s.rt.Sessions.CurrentUser(r)
	if user == nil {
		ret := s.path(r.URL.Path)
		if r.URL.RawQuery != "" {
			ret += "?" + r.URL.RawQuery
		}
		s.redirect(w, r, "/login?returnUrl="+url.QueryEscape(ret), http.StatusFound)
		return nil
	}
	return user
}

func (s *Server) profilePage(w http.ResponseWriter, r *http.Request) {
	user := s.requireUserHTML(w, r)
	if user == nil {
		return
	}
	s.rememberSessionClient(w, r, r.URL.Query().Get("clientId"))
	if r.URL.Query().Get("clientId") == "" {
		s.rememberSessionClient(w, r, r.URL.Query().Get("client_id"))
	}
	model := s.pageModel(r, "page.profile", user)
	model["activePage"] = "profile"
	model["profileNameValue"] = user.Name
	if strings.TrimSpace(user.AuthProvider) == "" {
		model["canLinkIdentityProviders"] = true
		model["identityProviders"] = s.identityProviderViews("/profile")
	}
	s.applyFlash(r, model)
	s.render(w, http.StatusOK, "profile", model)
}

func (s *Server) profileUpdate(w http.ResponseWriter, r *http.Request) {
	user := s.requireUserHTML(w, r)
	if user == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	name := r.Form.Get("name")
	if err := s.rt.UserReg.UpdateName(user.ID, name); err != nil {
		model := s.pageModel(r, "page.profile", user)
		model["activePage"] = "profile"
		model["error"] = err.Error()
		model["profileNameValue"] = name
		s.render(w, http.StatusBadRequest, "profile", model)
		return
	}
	s.redirect(w, r, "/profile?messageKey=flash.profile.nameUpdated", http.StatusFound)
}

func (s *Server) changePasswordPage(w http.ResponseWriter, r *http.Request) {
	user := s.requireUserHTML(w, r)
	if user == nil {
		return
	}
	model := s.passwordPageModel(r, user)
	s.applyFlash(r, model)
	s.render(w, http.StatusOK, "changePassword", model)
}

func (s *Server) changePasswordUpdate(w http.ResponseWriter, r *http.Request) {
	user := s.requireUserHTML(w, r)
	if user == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	next := r.Form.Get("newPassword")
	confirm := r.Form.Get("confirmPassword")
	creating := !user.HasLocalPassword()
	if next != confirm {
		model := s.passwordPageModel(r, user)
		model["error"] = s.rt.Messages.Resolve(s.lang(r), "error.password.mismatch", "passwords do not match")
		s.render(w, http.StatusBadRequest, "changePassword", model)
		return
	}
	var err error
	if creating {
		err = s.rt.UserReg.SetLocalPassword(user.ID, next)
	} else {
		err = s.rt.UserReg.UpdatePassword(user.ID, r.Form.Get("currentPassword"), next)
	}
	if err != nil {
		model := s.passwordPageModel(r, user)
		model["error"] = s.rt.Messages.Resolve(s.lang(r), userErrorKey(err), err.Error())
		s.render(w, http.StatusBadRequest, "changePassword", model)
		return
	}
	if creating {
		s.redirect(w, r, "/profile/password?messageKey=flash.password.created", http.StatusFound)
		return
	}
	s.redirect(w, r, "/profile/password?messageKey=flash.password.updated", http.StatusFound)
}

func (s *Server) removePassword(w http.ResponseWriter, r *http.Request) {
	user := s.requireUserHTML(w, r)
	if user == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	if err := s.rt.UserReg.RemoveLocalPassword(user.ID); err != nil {
		model := s.passwordPageModel(r, user)
		model["error"] = s.rt.Messages.Resolve(s.lang(r), userErrorKey(err), err.Error())
		s.render(w, http.StatusBadRequest, "changePassword", model)
		return
	}
	s.redirect(w, r, "/profile?messageKey=flash.password.removed", http.StatusFound)
}

func (s *Server) passwordPageModel(r *http.Request, user *model.User) map[string]any {
	model := s.pageModel(r, "page.changePassword", user)
	model["activePage"] = "profile"
	hasPassword := user.HasLocalPassword()
	model["hasLocalPassword"] = hasPassword
	model["creatingPassword"] = !hasPassword
	model["canRemovePassword"] = hasPassword && strings.TrimSpace(user.AuthProvider) != "" && strings.TrimSpace(user.ExternalSubject) != ""
	model["totpEnabled"] = user.IsTotpEnabled()
	model["removePasswordConfirm"] = s.rt.Messages.Resolve(s.lang(r), "password.removeConfirm", "Remove your local password?")
	return model
}

func (s *Server) profile2faPage(w http.ResponseWriter, r *http.Request) {
	user := s.requireUserHTML(w, r)
	if user == nil {
		return
	}
	if !user.HasLocalPassword() {
		s.redirect(w, r, "/profile?messageKey=flash.profile.2faNeedsPassword", http.StatusFound)
		return
	}
	model := s.pageModel(r, "page.profile2fa", user)
	model["activePage"] = "profile"
	model["totpEnabled"] = user.IsTotpEnabled()
	model["disable2faConfirm"] = s.rt.Messages.Resolve(s.lang(r), "profile2fa.disableConfirm", "Disable two-factor authentication?")
	s.applyFlash(r, model)
	if !user.IsTotpEnabled() && s.rt.TotpSetup != nil {
		if secret, ok := s.rt.TotpSetup.Peek(user.ID); ok {
			model["setupMode"] = true
			model["totpSecret"] = secret
			model["otpAuthUri"] = security.BuildOtpAuthURI(user.Email, secret, s.rt.Config.Server.EffectiveTitle())
		}
	}
	s.render(w, http.StatusOK, "profile2fa", model)
}

func (s *Server) profile2faSetup(w http.ResponseWriter, r *http.Request) {
	user := s.requireUserHTML(w, r)
	if user == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	if !user.HasLocalPassword() {
		s.redirect(w, r, "/profile?messageKey=flash.profile.2faNeedsPassword", http.StatusFound)
		return
	}
	if _, err := s.rt.UserReg.BeginTotpSetup(user.ID); err != nil {
		s.redirect(w, r, "/profile/2fa?errorKey="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	s.redirect(w, r, "/profile/2fa", http.StatusFound)
}

func (s *Server) profile2faConfirm(w http.ResponseWriter, r *http.Request) {
	user := s.requireUserHTML(w, r)
	if user == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	if !user.HasLocalPassword() {
		s.redirect(w, r, "/profile?messageKey=flash.profile.2faNeedsPassword", http.StatusFound)
		return
	}
	if err := s.rt.UserReg.ConfirmTotpSetup(user.ID, r.Form.Get("code")); err != nil {
		s.redirect(w, r, "/profile/2fa?errorKey="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	s.redirect(w, r, "/profile/2fa?messageKey=flash.profile.2faEnabled", http.StatusFound)
}

func (s *Server) profile2faDisable(w http.ResponseWriter, r *http.Request) {
	user := s.requireUserHTML(w, r)
	if user == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	if err := s.rt.UserReg.DisableTotpWithCredentials(user.ID, r.Form.Get("password"), r.Form.Get("code")); err != nil {
		s.redirect(w, r, "/profile/2fa?errorKey="+url.QueryEscape(userErrorKey(err)), http.StatusFound)
		return
	}
	s.redirect(w, r, "/profile/2fa?messageKey=flash.profile.2faDisabled", http.StatusFound)
}
