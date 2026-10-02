package runtime

import (
	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/i18n"
	"github.com/gcolin/go-sso/internal/mail"
	"github.com/gcolin/go-sso/internal/oauth"
	"github.com/gcolin/go-sso/internal/security"
	"github.com/gcolin/go-sso/internal/templates"
	"github.com/gcolin/go-sso/internal/themes"
	"github.com/gcolin/go-sso/web"
)

// Runtime wires SSO components similarly to Java SsoRuntime.create.
type Runtime struct {
	Config            *config.AppConfig
	Loader            *config.Loader
	JWT               *security.JwtService
	Users             *security.UserDirectory
	Passwords         *security.PasswordVerifier
	UserReg           *security.UserRegistry
	TotpSetup         *security.TotpSetupStore
	Sessions          *security.SessionCookies
	RateLimit         *security.LoginRateLimiter
	Clients           *oauth.OAuthClientRegistry
	OAuth             *oauth.OAuthService
	AuthCodes         *oauth.AuthorizationCodeStore
	AuthRequests      *oauth.AuthorizationRequestStore
	Consent           *oauth.ConsentStore
	IdProviders       *oauth.IdentityProviderRegistry
	ExternalOAuth     *oauth.ExternalOAuthService
	Email             *mail.EmailService
	AccountVerify     *mail.AccountVerificationService
	Messages          *i18n.Messages
	Templates         *templates.Renderer
	Themes            *themes.Registry

	Jwt          *security.JwtService
	UserRegistry *security.UserRegistry
	RateLimiter  *security.LoginRateLimiter
	OAuthClients *oauth.OAuthClientRegistry
}

func New(cfg *config.AppConfig, loader *config.Loader) (*Runtime, error) {
	return Create(cfg, loader)
}

func Create(cfg *config.AppConfig, loader *config.Loader) (*Runtime, error) {
	jwt, err := security.NewJwtService(cfg)
	if err != nil {
		return nil, err
	}
	msgs, err := templates.NewMessages()
	if err != nil {
		return nil, err
	}
	tpl := templates.New(msgs)
	themeReg := themes.New(web.FS, config.ResolveThemesDir(loader.Path(), cfg.Server.ThemesDir))
	tpl.SetThemes(themeReg)
	users := security.NewUserDirectory(cfg)
	totpSetup := security.NewTotpSetupStore()
	userRegistry := security.NewUserRegistry(cfg, loader, users, totpSetup)
	passwords := security.NewPasswordVerifier(users)
	sessions := security.NewSessionCookies(cfg, jwt, users)
	rateLimiter := security.NewLoginRateLimiter(cfg)
	authCodes := oauth.NewAuthorizationCodeStore()
	authRequests := oauth.NewAuthorizationRequestStore()
	consent := oauth.NewConsentStore()
	oauthClients := oauth.NewOAuthClientRegistry(cfg, loader)
	oauthSvc := oauth.NewOAuthService(cfg, oauthClients, users, jwt, authCodes, authRequests, consent)
	idProviders := oauth.NewIdentityProviderRegistry(cfg)
	extStates := oauth.NewExternalOAuthStateStore()
	extOAuth := oauth.NewExternalOAuthService(cfg, idProviders, extStates, userRegistry)
	emailSvc := mail.NewEmailService(cfg)
	accountVerify := mail.NewAccountVerificationService(cfg, emailSvc, tpl, jwt, userRegistry, msgs)

	return &Runtime{
		Config:        cfg,
		Loader:        loader,
		JWT:           jwt,
		Jwt:           jwt,
		Users:         users,
		Passwords:     passwords,
		UserReg:       userRegistry,
		UserRegistry:  userRegistry,
		TotpSetup:     totpSetup,
		Sessions:      sessions,
		RateLimit:     rateLimiter,
		RateLimiter:   rateLimiter,
		Clients:       oauthClients,
		OAuthClients:  oauthClients,
		OAuth:         oauthSvc,
		AuthCodes:     authCodes,
		AuthRequests:  authRequests,
		Consent:       consent,
		IdProviders:   idProviders,
		ExternalOAuth: extOAuth,
		Email:         emailSvc,
		AccountVerify: accountVerify,
		Messages:      msgs,
		Templates:     tpl,
		Themes:        themeReg,
	}, nil
}
