package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gcolin/go-sso/internal/model"
	"github.com/gcolin/go-sso/internal/security"
)

func (s *Server) emailLoginAllowed() bool {
	return s.rt.EmailLogin != nil && s.rt.EmailLogin.IsEnabled()
}

func (s *Server) loginEmailForm(w http.ResponseWriter, r *http.Request) {
	if !s.emailLoginAllowed() {
		s.renderErrorPage(w, r, "error.loginEmail.disabled")
		return
	}
	returnURL := r.URL.Query().Get("returnUrl")
	if strings.TrimSpace(returnURL) == "" {
		returnURL = "/"
	} else {
		returnURL = s.rt.ExternalOAuth.SanitizeReturnURL(returnURL)
	}
	clientID := strings.TrimSpace(r.URL.Query().Get("clientId"))
	if clientID == "" {
		clientID = clientIDFromReturnURL(returnURL)
	}
	s.renderLoginEmail(w, r, returnURL, clientID, r.URL.Query().Get("messageKey"), r.URL.Query().Get("errorKey"), "")
}

func (s *Server) loginEmailSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.emailLoginAllowed() {
		s.renderErrorPage(w, r, "error.loginEmail.disabled")
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	email := strings.TrimSpace(r.Form.Get("email"))
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
	if retry := s.rt.RateLimit.CheckAndRecord("email-login:" + clientIP(r)); retry > 0 {
		s.renderLoginEmail(w, r, returnURL, clientID, "", "error.loginEmail.rateLimited", email)
		return
	}
	if email == "" || !strings.Contains(email, "@") {
		s.renderLoginEmail(w, r, returnURL, clientID, "", "error.login.invalidCredentials", email)
		return
	}

	token, err := s.rt.EmailLogin.StartChallenge(email, returnURL, clientID, s.lang(r))
	if err != nil {
		s.renderLoginEmail(w, r, returnURL, clientID, "", "error.mail.sendFailed", email)
		return
	}
	s.rt.Sessions.SetPendingEmailLoginToken(w, token)
	q := url.Values{}
	q.Set("messageKey", "flash.loginEmail.codeSent")
	s.redirect(w, r, "/login/email/verify?"+q.Encode(), http.StatusFound)
}

func (s *Server) loginEmailVerifyForm(w http.ResponseWriter, r *http.Request) {
	if !s.emailLoginAllowed() {
		s.renderErrorPage(w, r, "error.loginEmail.disabled")
		return
	}
	pending, ok := s.rt.Sessions.ResolvePendingEmailLogin(r)
	if !ok || pending == nil {
		s.redirect(w, r, "/login/email?errorKey="+url.QueryEscape("error.loginEmail.expired"), http.StatusFound)
		return
	}
	s.renderLoginEmailVerify(w, r, pending, r.URL.Query().Get("messageKey"), r.URL.Query().Get("errorKey"))
}

func (s *Server) loginEmailVerifySubmit(w http.ResponseWriter, r *http.Request) {
	if !s.emailLoginAllowed() {
		s.renderErrorPage(w, r, "error.loginEmail.disabled")
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	pending, ok := s.rt.Sessions.ResolvePendingEmailLogin(r)
	if !ok || pending == nil {
		s.redirect(w, r, "/login/email?errorKey="+url.QueryEscape("error.loginEmail.expired"), http.StatusFound)
		return
	}
	if retry := s.rt.RateLimit.CheckAndRecord("email-login-verify:" + clientIP(r) + ":" + pending.JTI); retry > 0 {
		s.renderLoginEmailVerify(w, r, pending, "", "error.loginEmail.rateLimited")
		return
	}
	code := strings.TrimSpace(r.Form.Get("code"))
	email, ok := s.rt.EmailLogin.VerifyChallenge(pending.JTI, code)
	if !ok {
		s.renderLoginEmailVerify(w, r, pending, "", "error.loginEmail.invalidCode")
		return
	}
	if email == "" {
		email = pending.Email
	}

	user, err := s.resolveEmailLoginUser(email)
	if err != nil || user == nil {
		s.rt.Sessions.ClearPendingEmailLoginCookie(w)
		key := "error.user.notFound"
		if err != nil {
			if _, ok := err.(*security.UserValidationError); ok {
				key = "error.login.invalidCredentials"
			}
		}
		s.redirect(w, r, "/login/email?errorKey="+url.QueryEscape(key), http.StatusFound)
		return
	}

	s.rt.Sessions.ClearPendingEmailLoginCookie(w)
	if pending.ClientID != "" {
		_ = s.rt.Sessions.WriteSessionForClient(w, user, pending.ClientID)
	} else {
		_ = s.rt.Sessions.WriteSession(w, user)
	}
	s.redirect(w, r, pending.ReturnURL, http.StatusFound)
}

func (s *Server) resolveEmailLoginUser(email string) (*model.User, error) {
	if u, ok := s.rt.UserReg.FindByEmail(email); ok {
		if !u.IsEmailVerified() {
			if err := s.rt.UserReg.MarkEmailVerified(u.ID); err != nil {
				return nil, err
			}
			u, _ = s.rt.UserReg.FindByID(u.ID)
		}
		return u, nil
	}
	return s.rt.UserReg.CreateVerifiedPasswordless(email)
}

func (s *Server) renderLoginEmail(w http.ResponseWriter, r *http.Request, returnURL, clientID, messageKey, errorKey, formEmail string) {
	model := s.pageModel(r, "page.loginEmail", nil)
	model["returnUrl"] = returnURL
	model["returnUrlEncoded"] = url.QueryEscape(returnURL)
	if clientID != "" {
		model["clientId"] = clientID
	}
	model["formEmail"] = formEmail
	s.applyClientTheme(r, model)
	if messageKey != "" {
		model["message"] = s.rt.Messages.Resolve(s.lang(r), messageKey, messageKey)
	}
	if errorKey != "" {
		model["error"] = s.rt.Messages.Resolve(s.lang(r), errorKey, errorKey)
	}
	s.render(w, http.StatusOK, "loginEmail", model)
}

func (s *Server) renderLoginEmailVerify(w http.ResponseWriter, r *http.Request, pending *security.PendingEmailLoginClaims, messageKey, errorKey string) {
	model := s.pageModel(r, "page.loginEmailVerify", nil)
	model["email"] = pending.Email
	model["returnUrl"] = pending.ReturnURL
	model["returnUrlEncoded"] = url.QueryEscape(pending.ReturnURL)
	if pending.ClientID != "" {
		model["clientId"] = pending.ClientID
	}
	s.applyClientTheme(r, model)
	if messageKey != "" {
		model["message"] = s.rt.Messages.Resolve(s.lang(r), messageKey, messageKey)
	}
	if errorKey != "" {
		model["error"] = s.rt.Messages.Resolve(s.lang(r), errorKey, errorKey)
	}
	s.render(w, http.StatusOK, "loginEmailVerify", model)
}
