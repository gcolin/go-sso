package security

import (
	"net/http"
	"strings"
	"time"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/model"
)

const (
	pending2FACookieSuffix         = "_pending_2fa"
	pendingRegistrationCookieSuffix = "_pending_registration"
)

// SessionCookies manages SSO session and pending-2FA cookies.
type SessionCookies struct {
	cfg   *config.AppConfig
	jwt   *JwtService
	users *UserDirectory
}

// SessionCookieService is an alias type name for Java parity.
type SessionCookieService = SessionCookies

func NewSessionCookies(cfg *config.AppConfig, jwt *JwtService, users *UserDirectory) *SessionCookies {
	return &SessionCookies{cfg: cfg, jwt: jwt, users: users}
}

func NewSessionCookieService(cfg *config.AppConfig, jwt *JwtService, dir *UserDirectory) *SessionCookies {
	return NewSessionCookies(cfg, jwt, dir)
}

func (s *SessionCookies) CookieName() string {
	return s.cfg.Security.EffectiveSessionCookieName()
}

func (s *SessionCookies) PendingCookieName() string {
	return s.CookieName() + pending2FACookieSuffix
}

func (s *SessionCookies) ResolveUser(r *http.Request) (*model.User, bool) {
	u := s.CurrentUser(r)
	if u == nil {
		return nil, false
	}
	return u, true
}

func (s *SessionCookies) CurrentUser(r *http.Request) *model.User {
	claims := s.CurrentSession(r)
	if claims == nil {
		return nil
	}
	user, found := s.users.FindByID(claims.UserID)
	if !found {
		return nil
	}
	return user
}

// CurrentSession returns parsed session claims, or nil.
func (s *SessionCookies) CurrentSession(r *http.Request) *SessionClaims {
	raw, ok := readCookie(r, s.CookieName())
	if !ok {
		return nil
	}
	claims, err := s.jwt.ParseSessionToken(raw)
	if err != nil {
		return nil
	}
	return claims
}

// CurrentClientID returns the OAuth client_id remembered in the session JWT, if any.
func (s *SessionCookies) CurrentClientID(r *http.Request) string {
	claims := s.CurrentSession(r)
	if claims == nil {
		return ""
	}
	return strings.TrimSpace(claims.ClientID)
}

func (s *SessionCookies) WriteSessionCookie(w http.ResponseWriter, user *model.User) error {
	return s.WriteSession(w, user)
}

func (s *SessionCookies) WriteSession(w http.ResponseWriter, user *model.User) error {
	return s.WriteSessionForClient(w, user, "")
}

// WriteSessionForClient issues a session cookie that remembers the OAuth client for theming.
func (s *SessionCookies) WriteSessionForClient(w http.ResponseWriter, user *model.User, clientID string) error {
	token, err := s.jwt.CreateSessionTokenForClient(user.ID, user.Email, user.PlatformRoles(), clientID)
	if err != nil {
		return err
	}
	s.setCookie(w, s.CookieName(), token, s.cfg.Security.EffectiveSessionTtlMinutes()*60)
	return nil
}

func (s *SessionCookies) ClearSessionCookie(w http.ResponseWriter) {
	s.ClearSession(w)
}

func (s *SessionCookies) ClearSession(w http.ResponseWriter) {
	s.setCookie(w, s.CookieName(), "", 0)
}

func (s *SessionCookies) WritePending2FACookie(w http.ResponseWriter, user *model.User, returnURL string) error {
	token, err := s.jwt.CreatePending2FAToken(user.ID, user.Email, returnURL)
	if err != nil {
		return err
	}
	s.setCookie(w, s.PendingCookieName(), token, 300)
	return nil
}

func (s *SessionCookies) ResolvePending2FA(r *http.Request) (*Pending2FAClaims, bool) {
	raw, ok := readCookie(r, s.PendingCookieName())
	if !ok {
		return nil, false
	}
	claims, err := s.jwt.ParsePending2FAToken(raw)
	if err != nil {
		return nil, false
	}
	return claims, true
}

func (s *SessionCookies) ClearPending2FACookie(w http.ResponseWriter) {
	s.setCookie(w, s.PendingCookieName(), "", 0)
}

func (s *SessionCookies) CreatePending2FAToken(user *model.User, returnURL string) (string, error) {
	return s.jwt.CreatePending2FAToken(user.ID, user.Email, returnURL)
}

func (s *SessionCookies) PendingRegistrationCookieName() string {
	return s.CookieName() + pendingRegistrationCookieSuffix
}

func (s *SessionCookies) WritePendingRegistrationCookie(w http.ResponseWriter, user *model.User, returnURL string) error {
	token, err := s.jwt.CreatePendingRegistrationToken(user.ID, user.Email, returnURL)
	if err != nil {
		return err
	}
	ttl := s.cfg.Security.EffectiveEmailVerificationTtlHours() * 3600
	s.setCookie(w, s.PendingRegistrationCookieName(), token, ttl)
	return nil
}

func (s *SessionCookies) ResolvePendingRegistration(r *http.Request) (*PendingRegistrationClaims, bool) {
	raw, ok := readCookie(r, s.PendingRegistrationCookieName())
	if !ok {
		return nil, false
	}
	claims, err := s.jwt.ParsePendingRegistrationToken(raw)
	if err != nil {
		return nil, false
	}
	return claims, true
}

func (s *SessionCookies) ClearPendingRegistrationCookie(w http.ResponseWriter) {
	s.setCookie(w, s.PendingRegistrationCookieName(), "", 0)
}

func (s *SessionCookies) setCookie(w http.ResponseWriter, name, value string, maxAgeSeconds int64) {
	cookiePath := "/"
	if p := s.cfg.Server.ContextPath(); p != "" {
		cookiePath = p
	}
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     cookiePath,
		MaxAge:   int(maxAgeSeconds),
		HttpOnly: true,
		Secure:   s.cfg.Security.SessionCookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
	if maxAgeSeconds <= 0 {
		c.MaxAge = -1
		c.Expires = time.Unix(0, 0)
	}
	http.SetCookie(w, c)
}

func readCookie(r *http.Request, name string) (string, bool) {
	c, err := r.Cookie(name)
	if err != nil || c == nil || strings.TrimSpace(c.Value) == "" {
		return "", false
	}
	return c.Value, true
}
