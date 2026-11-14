package mail

import (
	"strings"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/i18n"
	"github.com/gcolin/go-sso/internal/security"
	"github.com/gcolin/go-sso/internal/templates"
)

// EmailLoginService issues email OTP challenges (RAM store + pending JWT cookie claims).
type EmailLoginService struct {
	cfg      *config.AppConfig
	email    HTMLSender
	tpl      *templates.Renderer
	jwt      *security.JwtService
	store    *security.EmailLoginOTPStore
	messages *i18n.Messages
}

func NewEmailLoginService(
	cfg *config.AppConfig,
	email HTMLSender,
	tpl *templates.Renderer,
	jwt *security.JwtService,
	store *security.EmailLoginOTPStore,
	messages *i18n.Messages,
) *EmailLoginService {
	return &EmailLoginService{
		cfg:      cfg,
		email:    email,
		tpl:      tpl,
		jwt:      jwt,
		store:    store,
		messages: messages,
	}
}

func (s *EmailLoginService) IsEnabled() bool {
	return s != nil &&
		s.cfg != nil &&
		s.cfg.Mail.LoginByEmailEnabled &&
		s.email != nil &&
		s.email.IsEnabled()
}

// StartChallenge creates jti + OTP, stores the hash, returns cookie JWT token, and emails the code.
func (s *EmailLoginService) StartChallenge(email, returnURL, clientID, lang string) (cookieToken string, err error) {
	if !s.IsEnabled() {
		return "", &VerificationException{Msg: "email login is not enabled"}
	}
	email = strings.TrimSpace(email)
	if email == "" || !strings.Contains(email, "@") {
		return "", &VerificationException{Msg: "email is invalid"}
	}
	if lang == "" {
		lang = "fr"
	}
	if returnURL == "" {
		returnURL = "/"
	}

	code, err := security.GenerateOTP6()
	if err != nil {
		return "", err
	}
	jti := security.NewTokenID()
	s.store.Put(jti, email, code, security.EmailLoginOTPTTLSeconds)

	token, err := s.jwt.CreatePendingEmailLoginToken(jti, email, returnURL, clientID)
	if err != nil {
		return "", err
	}

	if err := s.sendLoginCodeEmail(email, code, lang); err != nil {
		return "", err
	}
	return token, nil
}

// VerifyChallenge consumes the OTP for the pending jti. Returns the email on success.
func (s *EmailLoginService) VerifyChallenge(jti, code string) (string, bool) {
	if s == nil || s.store == nil {
		return "", false
	}
	return s.store.Consume(jti, code)
}

func (s *EmailLoginService) sendLoginCodeEmail(toAddress, code, lang string) error {
	appTitle := s.cfg.Server.EffectiveTitle()
	ttlMinutes := security.EmailLoginOTPTTLSeconds / 60
	subject := s.messages.Get(lang, "email.loginCode.subject", appTitle)
	htmlBody, err := s.tpl.Render("email/loginCode", map[string]any{
		"lang":       lang,
		"code":       code,
		"ttlMinutes": ttlMinutes,
		"appTitle":   appTitle,
	})
	if err != nil {
		return err
	}
	return s.email.SendHTML(toAddress, subject, htmlBody)
}
