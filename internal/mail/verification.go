package mail

import (
	"net/url"
	"strings"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/i18n"
	"github.com/gcolin/go-sso/internal/model"
	"github.com/gcolin/go-sso/internal/security"
	"github.com/gcolin/go-sso/internal/templates"
)

// VerificationException is returned for verification business errors.
type VerificationException struct {
	Msg string
}

func (e *VerificationException) Error() string {
	if e == nil {
		return "verification error"
	}
	return e.Msg
}

// AccountVerificationService issues JWT verify links and marks emails verified.
type AccountVerificationService struct {
	cfg      *config.AppConfig
	email    HTMLSender
	tpl      *templates.Renderer
	jwt      *security.JwtService
	users    *security.UserRegistry
	messages *i18n.Messages
}

// HTMLSender sends HTML emails (EmailService implements this).
type HTMLSender interface {
	IsEnabled() bool
	SendHTML(toAddress, subject, htmlBody string) error
}

func NewAccountVerificationService(
	cfg *config.AppConfig,
	email HTMLSender,
	tpl *templates.Renderer,
	jwt *security.JwtService,
	users *security.UserRegistry,
	messages *i18n.Messages,
) *AccountVerificationService {
	return &AccountVerificationService{
		cfg:      cfg,
		email:    email,
		tpl:      tpl,
		jwt:      jwt,
		users:    users,
		messages: messages,
	}
}

func (s *AccountVerificationService) IsEnabled() bool {
	return s != nil && s.email != nil && s.email.IsEnabled()
}

func (s *AccountVerificationService) SendVerificationEmail(user *model.User, lang string) error {
	if !s.IsEnabled() {
		return &VerificationException{Msg: "email verification is not enabled"}
	}
	if user == nil || user.IsEmailVerified() || user.RequiresFederatedLogin() {
		return nil
	}
	if lang == "" {
		lang = "fr"
	}

	token, err := s.jwt.CreateEmailVerificationToken(user.ID, user.Email)
	if err != nil {
		return err
	}
	verifyURL := s.buildVerifyURL(token)
	appTitle := s.cfg.Server.EffectiveTitle()
	userName := strings.TrimSpace(user.Name)
	if userName == "" {
		userName = user.Email
	}
	ttlHours := s.cfg.Security.EffectiveEmailVerificationTtlHours()

	subject := s.messages.Get(lang, "email.verify.subject", appTitle)
	htmlBody, err := s.tpl.Render("email/verifyAccount", map[string]any{
		"lang":      lang,
		"userName":  userName,
		"verifyUrl": verifyURL,
		"ttlHours":  ttlHours,
		"appTitle":  appTitle,
	})
	if err != nil {
		return err
	}
	return s.email.SendHTML(user.Email, subject, htmlBody)
}

func (s *AccountVerificationService) VerifyEmail(token string) (*model.User, error) {
	claims, err := s.jwt.ParseEmailVerificationToken(token)
	if err != nil || claims == nil {
		return nil, nil
	}
	user, ok := s.users.FindByID(claims.UserID)
	if !ok || user == nil {
		return nil, nil
	}
	if !strings.EqualFold(user.Email, claims.Email) {
		return nil, nil
	}
	if user.IsEmailVerified() {
		return user, nil
	}
	if err := s.users.MarkEmailVerified(claims.UserID); err != nil {
		return nil, err
	}
	user, _ = s.users.FindByID(claims.UserID)
	return user, nil
}

func (s *AccountVerificationService) ResendVerificationEmail(email, lang string) error {
	if !s.IsEnabled() {
		return &VerificationException{Msg: "email verification is not enabled"}
	}
	user, ok := s.users.FindByEmail(email)
	if !ok || user == nil {
		return &VerificationException{Msg: "user not found"}
	}
	if user.IsEmailVerified() {
		return &VerificationException{Msg: "email already verified"}
	}
	if user.RequiresFederatedLogin() {
		return &VerificationException{Msg: "federated accounts do not require email verification"}
	}
	return s.SendVerificationEmail(user, lang)
}

func (s *AccountVerificationService) buildVerifyURL(token string) string {
	base := strings.TrimRight(s.cfg.Server.PublicBaseURL, "/")
	return base + "/verify-email?token=" + url.QueryEscape(token)
}
