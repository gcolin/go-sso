package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/gcolin/go-sso/internal/mail"
)

func (s *Server) verifyEmailPage(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		s.renderVerifyEmailError(w, r, "verifyEmail.error.invalidToken")
		return
	}
	user, err := s.rt.AccountVerify.VerifyEmail(token)
	if err != nil || user == nil {
		s.renderVerifyEmailError(w, r, "verifyEmail.error.invalidToken")
		return
	}
	model := s.pageModel(r, "page.verifyEmailSuccess", nil)
	model["email"] = user.Email
	s.render(w, http.StatusOK, "verifyEmailSuccess", model)
}

func (s *Server) resendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	if !s.requireCSRF(w, r) {
		return
	}
	email := strings.TrimSpace(r.Form.Get("email"))
	returnURL := s.sanitizeRegisterReturnURL(r.Form.Get("returnUrl"))
	pending := r.Form.Get("pending") == "1"
	pendingPath := "/register/pending?email=" + url.QueryEscape(email) + "&returnUrl=" + url.QueryEscape(returnURL)
	if retry := s.rt.RateLimit.CheckAndRecord("verify:" + clientIP(r)); retry > 0 {
		if pending {
			s.redirect(w, r, pendingPath+"&errorKey="+url.QueryEscape("error.login.rateLimited"), http.StatusFound)
			return
		}
		s.renderLogin(w, r, returnURL, "", "", "error.login.rateLimited")
		return
	}
	err := s.rt.AccountVerify.ResendVerificationEmail(email, s.lang(r))
	if err != nil {
		errorKey := "error.mail.sendFailed"
		var ve *mail.VerificationException
		if errors.As(err, &ve) {
			errorKey = "error.login.emailNotVerified"
		}
		if pending {
			s.redirect(w, r, pendingPath+"&errorKey="+url.QueryEscape(errorKey), http.StatusFound)
			return
		}
		s.renderLogin(w, r, returnURL, "", "", errorKey)
		return
	}
	if pending {
		// Only refresh an existing pending-registration cookie from this browser.
		// Never mint one from resend alone (that would allow session theft after verify).
		if claims, ok := s.rt.Sessions.ResolvePendingRegistration(r); ok && claims != nil &&
			strings.EqualFold(claims.Email, email) {
			if user, found := s.rt.UserReg.FindByEmail(email); found && user != nil && user.ID == claims.UserID {
				_ = s.rt.Sessions.WritePendingRegistrationCookie(w, user, returnURL)
			}
		}
		s.redirect(w, r, pendingPath+"&messageKey="+url.QueryEscape("flash.user.verificationSent"), http.StatusFound)
		return
	}
	s.renderLogin(w, r, returnURL, "", "flash.user.verificationSent", "")
}

func (s *Server) renderVerifyEmailError(w http.ResponseWriter, r *http.Request, errorKey string) {
	model := s.pageModel(r, "page.verifyEmailError", nil)
	model["error"] = s.rt.Messages.Resolve(s.lang(r), errorKey, errorKey)
	s.render(w, http.StatusOK, "verifyEmailError", model)
}

func (s *Server) adminUserResendVerification(w http.ResponseWriter, r *http.Request) {
	if s.requireAdminHTML(w, r) == nil {
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	userID := r.Form.Get("userId")
	user, ok := s.rt.UserReg.FindByID(userID)
	if !ok || user == nil {
		s.redirect(w, r, "/admin/users?errorKey="+url.QueryEscape("error.user.notFound"), http.StatusFound)
		return
	}
	if err := s.rt.AccountVerify.SendVerificationEmail(user, s.lang(r)); err != nil {
		s.redirect(w, r, "/admin/users?errorKey="+url.QueryEscape("error.mail.sendFailed"), http.StatusFound)
		return
	}
	s.redirect(w, r, "/admin/users?messageKey=flash.user.verificationSent", http.StatusFound)
}
