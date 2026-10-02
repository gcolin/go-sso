package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gcolin/go-sso/internal/model"
)

func (s *Server) registerForm(w http.ResponseWriter, r *http.Request) {
	if !s.publicRegistrationAllowed() {
		s.renderErrorPage(w, r, s.publicRegistrationDenyKey())
		return
	}
	if s.rt.Sessions.CurrentUser(r) != nil {
		s.redirect(w, r, "/", http.StatusFound)
		return
	}
	returnURL := s.sanitizeRegisterReturnURL(r.URL.Query().Get("returnUrl"))
	s.renderRegister(w, r, returnURL, "", "", "")
}

func (s *Server) registerSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.publicRegistrationAllowed() {
		s.renderErrorPage(w, r, s.publicRegistrationDenyKey())
		return
	}
	if s.rt.Sessions.CurrentUser(r) != nil {
		s.redirect(w, r, "/", http.StatusFound)
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	returnURL := s.sanitizeRegisterReturnURL(r.Form.Get("returnUrl"))
	email := r.Form.Get("email")
	name := r.Form.Get("name")
	password := r.Form.Get("password")
	confirmPassword := r.Form.Get("confirmPassword")

	if retry := s.rt.RateLimit.CheckAndRecord("register:" + clientIP(r)); retry > 0 {
		s.renderRegister(w, r, returnURL, email, name, "error.register.rateLimited")
		return
	}
	if password == "" || password != confirmPassword {
		s.renderRegister(w, r, returnURL, email, name, "error.password.mismatch")
		return
	}

	resolvedName := strings.TrimSpace(name)
	if resolvedName == "" {
		resolvedName = strings.TrimSpace(email)
	}

	_, err := s.rt.UserReg.Create(email, resolvedName, model.TypeUser, password, 0)
	if err != nil {
		s.renderRegister(w, r, returnURL, email, name, userErrorKey(err))
		return
	}
	if s.rt.AccountVerify.IsEnabled() {
		user, ok := s.rt.UserReg.FindByEmail(email)
		if ok && user != nil && !user.IsEmailVerified() {
			if err := s.rt.AccountVerify.SendVerificationEmail(user, s.lang(r)); err != nil {
				s.redirect(w, r, "/?messageKey="+url.QueryEscape("flash.register.createdMailFailed")+
					"&returnUrl="+url.QueryEscape(returnURL), http.StatusFound)
				return
			}
			_ = s.rt.Sessions.WritePendingRegistrationCookie(w, user, returnURL)
			s.redirect(w, r, "/register/pending?email="+url.QueryEscape(strings.TrimSpace(email))+
				"&returnUrl="+url.QueryEscape(returnURL), http.StatusFound)
			return
		}
	}
	s.redirect(w, r, "/?messageKey="+url.QueryEscape("flash.register.success")+
		"&returnUrl="+url.QueryEscape(returnURL), http.StatusFound)
}

func (s *Server) registerPendingForm(w http.ResponseWriter, r *http.Request) {
	if s.rt.Sessions.CurrentUser(r) != nil {
		s.redirect(w, r, "/", http.StatusFound)
		return
	}
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	returnURL := s.sanitizeRegisterReturnURL(r.URL.Query().Get("returnUrl"))
	if email == "" {
		s.redirect(w, r, "/register?returnUrl="+url.QueryEscape(returnURL), http.StatusFound)
		return
	}
	s.renderRegisterPending(w, r, email, returnURL, r.URL.Query().Get("messageKey"), r.URL.Query().Get("errorKey"))
}

func (s *Server) registerPendingSubmit(w http.ResponseWriter, r *http.Request) {
	if s.rt.Sessions.CurrentUser(r) != nil {
		s.redirect(w, r, "/", http.StatusFound)
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	email := strings.TrimSpace(r.Form.Get("email"))
	returnURL := s.sanitizeRegisterReturnURL(r.Form.Get("returnUrl"))
	if email == "" {
		s.redirect(w, r, "/register?returnUrl="+url.QueryEscape(returnURL), http.StatusFound)
		return
	}
	user, ok := s.rt.UserReg.FindByEmail(email)
	if !ok || user == nil {
		s.renderRegisterPending(w, r, email, returnURL, "", "registerPending.notVerified")
		return
	}
	if !user.IsEmailVerified() {
		s.renderRegisterPending(w, r, email, returnURL, "", "registerPending.notVerified")
		return
	}

	claims, hasPending := s.rt.Sessions.ResolvePendingRegistration(r)
	if hasPending && claims != nil &&
		strings.EqualFold(claims.Email, email) &&
		claims.UserID == user.ID {
		if claims.ReturnURL != "" && returnURL == "/" {
			returnURL = s.sanitizeRegisterReturnURL(claims.ReturnURL)
		}
		s.rt.Sessions.ClearPendingRegistrationCookie(w)
		if err := s.rt.Sessions.WriteSession(w, user); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, s.appReturnURL(returnURL), http.StatusFound)
		return
	}

	s.rt.Sessions.ClearPendingRegistrationCookie(w)
	s.redirect(w, r, "/?messageKey="+url.QueryEscape("flash.register.success")+
		"&returnUrl="+url.QueryEscape(returnURL), http.StatusFound)
}

func (s *Server) renderRegisterPending(w http.ResponseWriter, r *http.Request, email, returnURL, messageKey, errorKey string) {
	model := s.pageModel(r, "page.registerPending", nil)
	model["email"] = email
	model["returnUrl"] = returnURL
	model["returnUrlEncoded"] = url.QueryEscape(returnURL)
	if messageKey != "" {
		model["message"] = s.rt.Messages.Resolve(s.lang(r), messageKey, messageKey)
	}
	if errorKey != "" {
		model["error"] = s.rt.Messages.Resolve(s.lang(r), errorKey, errorKey)
	}
	s.render(w, http.StatusOK, "registerPending", model)
}

func (s *Server) renderRegister(w http.ResponseWriter, r *http.Request, returnURL, email, name, errorKey string) {
	model := s.pageModel(r, "page.register", nil)
	model["returnUrl"] = returnURL
	model["returnUrlEncoded"] = url.QueryEscape(returnURL)
	model["formEmail"] = email
	model["formName"] = name
	if errorKey != "" {
		model["error"] = s.rt.Messages.Resolve(s.lang(r), errorKey, errorKey)
	}
	s.render(w, http.StatusOK, "register", model)
}

func (s *Server) renderErrorPage(w http.ResponseWriter, r *http.Request, messageKey string) {
	model := s.pageModel(r, "page.error", nil)
	model["message"] = s.rt.Messages.Resolve(s.lang(r), messageKey, messageKey)
	s.render(w, http.StatusOK, "error", model)
}

func (s *Server) sanitizeRegisterReturnURL(returnURL string) string {
	if strings.TrimSpace(returnURL) == "" {
		return "/"
	}
	return s.rt.ExternalOAuth.SanitizeReturnURL(returnURL)
}

// publicRegistrationAllowed requires both the security flag and working mail
// (email verification). Local signup without mail verification enables email squatting.
func (s *Server) publicRegistrationAllowed() bool {
	return s.rt.Config.Security.PublicRegistrationEnabled &&
		s.rt.AccountVerify != nil && s.rt.AccountVerify.IsEnabled()
}

func (s *Server) publicRegistrationDenyKey() string {
	if s.rt.Config.Security.PublicRegistrationEnabled &&
		(s.rt.AccountVerify == nil || !s.rt.AccountVerify.IsEnabled()) {
		return "error.register.mailRequired"
	}
	return "error.register.disabled"
}

func userErrorKey(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case msg == "name is required":
		return "error.user.nameRequired"
	case msg == "name is too long":
		return "error.user.nameTooLong"
	case msg == "id is required":
		return "error.user.idRequired"
	case msg == "email is required":
		return "error.user.emailRequired"
	case msg == "password is required":
		return "error.user.passwordRequired"
	case msg == "current password is required":
		return "error.user.currentPasswordRequired"
	case msg == "current password is invalid":
		return "error.user.currentPasswordInvalid"
	case msg == "password is not set":
		return "error.password.notSet"
	case msg == "password is already set":
		return "error.password.alreadySet"
	case msg == "cannot remove password without linked identity provider":
		return "error.password.removeNeedsFederation"
	case msg == "password must be at least 8 characters":
		return "error.password.tooShort"
	case msg == "new password must differ from current password":
		return "error.user.newPasswordMustDiffer"
	case msg == "type is required":
		return "error.user.typeRequired"
	case msg == "type must be 'user' or 'admin'":
		return "error.user.typeInvalid"
	case msg == "user id is required":
		return "error.user.userIdRequired"
	case strings.HasPrefix(msg, "user already exists:"):
		return "error.user.alreadyExists"
	case strings.HasPrefix(msg, "email already in use:"):
		return "error.user.emailInUse"
	case strings.HasPrefix(msg, "user not found:"):
		return "error.user.notFound"
	case msg == "cannot delete the last user":
		return "error.user.cannotDeleteLast"
	case msg == "cannot delete the last admin":
		return "error.user.cannotDeleteLastAdmin"
	case msg == "cannot delete your own account":
		return "error.user.cannotDeleteSelf"
	case msg == "totp is already enabled":
		return "error.user.totpAlreadyEnabled"
	case msg == "totp is not enabled":
		return "error.user.totpNotEnabled"
	case msg == "totp setup expired", msg == "totp setup expired or not started":
		return "error.user.totpSetupExpired"
	case msg == "totp code is required":
		return "error.user.totpCodeRequired"
	case msg == "totp code must be 6 digits":
		return "error.user.totpCodeInvalidFormat"
	case msg == "totp code is invalid":
		return "error.user.totpCodeInvalid"
	default:
		return msg
	}
}
