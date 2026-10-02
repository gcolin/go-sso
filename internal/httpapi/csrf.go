package httpapi

import (
	"net/http"
)

// csrfSubject returns the user id the CSRF token must be bound to for this request.
// Prefer full session, then pending 2FA, then pending registration; empty = anonymous.
func (s *Server) csrfSubject(r *http.Request) string {
	if u := s.rt.Sessions.CurrentUser(r); u != nil {
		return u.ID
	}
	if p, ok := s.rt.Sessions.ResolvePending2FA(r); ok && p != nil {
		return p.UserID
	}
	if p, ok := s.rt.Sessions.ResolvePendingRegistration(r); ok && p != nil {
		return p.UserID
	}
	return ""
}

// requireCSRF validates the signed CSRF JWT from form field _csrf.
// Call after ensuring the request body can be parsed as a form.
func (s *Server) requireCSRF(w http.ResponseWriter, r *http.Request) bool {
	_ = r.ParseForm()
	token := r.Form.Get("_csrf")
	if err := s.rt.JWT.ValidateCsrfToken(token, s.csrfSubject(r)); err != nil {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return false
	}
	return true
}
