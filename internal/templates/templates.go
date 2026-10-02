package templates

import (
	"fmt"
	"io/fs"
	"net/url"
	"strings"

	"github.com/gcolin/go-sso/internal/i18n"
	"github.com/gcolin/go-sso/internal/model"
	"github.com/gcolin/go-sso/internal/mustache"
	"github.com/gcolin/go-sso/internal/themes"
	"github.com/gcolin/go-sso/web"
)

// Renderer renders SSO Mustache pages with layout + i18n (Java SsoTemplates parity).
type Renderer struct {
	messages *i18n.Messages
	themes   *themes.Registry
	fs       fs.FS
}

func New(messages *i18n.Messages) *Renderer {
	return &Renderer{messages: messages, fs: web.FS, themes: themes.New(web.FS, "")}
}

// SetThemes replaces the theme registry (disk overlay / config).
func (r *Renderer) SetThemes(reg *themes.Registry) {
	if reg != nil {
		r.themes = reg
	}
}

func (r *Renderer) Themes() *themes.Registry {
	return r.themes
}

func NewMessages() (*i18n.Messages, error) {
	m := i18n.New()
	if err := m.LoadFS(web.FS, "i18n"); err != nil {
		return nil, err
	}
	return m, nil
}

func (r *Renderer) Render(template string, model map[string]any) (string, error) {
	name := normalize(template)
	ctx := map[string]any{}
	for k, v := range model {
		ctx[k] = v
	}
	lang := "fr"
	if v, ok := ctx["lang"].(string); ok && v != "" {
		lang = v
	}
	ctx["t"] = r.messages.Tree(lang)
	ctx["_messages"] = r.messages
	ctx["m"] = mustache.Lambda(func(body string) string {
		return formatMessage(r.messages, lang, body)
	})
	enrich(ctx, name)

	theme := themes.BaseTheme
	if v, ok := ctx["theme"].(string); ok && strings.TrimSpace(v) != "" {
		theme = strings.TrimSpace(v)
	}
	baseName := stripExt(name)
	if strings.HasPrefix(baseName, "admin/") || strings.HasPrefix(baseName, "email/") {
		theme = themes.BaseTheme
		delete(ctx, "themeCss")
		delete(ctx, "themeColor")
	}
	ctx["theme"] = theme
	ctx["_theme"] = theme

	body, err := r.renderFile(name, ctx, theme)
	if err != nil {
		return "", err
	}
	layout := layoutFor(name)
	if layout == "" {
		return body, nil
	}
	ctx["content"] = body
	return r.renderFile(layout, ctx, theme)
}

func (r *Renderer) renderFile(name string, ctx map[string]any, theme string) (string, error) {
	src, err := r.load(theme, name)
	if err != nil {
		return "", err
	}
	return mustache.Compile(src).RenderWith(ctx, func(partial string) string {
		s, err := r.load(theme, partial)
		if err != nil {
			return ""
		}
		return s
	}), nil
}

func (r *Renderer) load(theme, name string) (string, error) {
	if r.themes == nil {
		return "", fmt.Errorf("themes registry not configured")
	}
	return r.themes.ResolveTemplate(theme, name)
}

// BaseModel builds the shared page context.
func (r *Renderer) BaseModel(titleKey, lang, basePath, appTitle string, user *model.User) map[string]any {
	if lang == "" {
		lang = "fr"
	}
	m := map[string]any{
		"pageTitle": r.messages.Get(lang, titleKey),
		"appTitle":  appTitle,
		"locale":    lang,
		"lang":      lang,
		"basePath":  basePath,
		"csrfToken": "", // filled by httpapi.pageModel (signed CSRF JWT)
		"theme":     themes.BaseTheme,
	}
	if user != nil {
		m["user"] = userView(user)
	}
	return m
}


func userView(u *model.User) map[string]any {
	return map[string]any{
		"id":               u.ID,
		"email":            u.Email,
		"name":             u.Name,
		"type":             u.AccountType(),
		"admin":            u.IsAdmin(),
		"totpEnabled":      u.IsTotpEnabled(),
		"hasLocalPassword": u.HasLocalPassword(),
		"authProvider":     u.AuthProvider,
	}
}

func enrich(ctx map[string]any, name string) {
	base := stripExt(name)
	if base == "home" {
		if _, ok := ctx["activePage"]; !ok {
			ctx["activePage"] = "home"
		}
	} else if base == "profile" || base == "changePassword" || base == "profile2fa" {
		if _, ok := ctx["activePage"]; !ok {
			ctx["activePage"] = "profile"
		}
	}
	if isAuthPage(base) {
		ctx["authPage"] = true
	}
	active, _ := ctx["activePage"].(string)
	ctx["navHomeActive"] = active == "home"
	ctx["navUsersActive"] = active == "users" || active == "user-form" || active == "users-new"
	ctx["navSettingsActive"] = active == "settings"
	ctx["navProfileActive"] = active == "profile"

	if ru, ok := ctx["returnUrl"].(string); ok {
		ctx["returnUrlEncoded"] = url.QueryEscape(ru)
	}

	if providers, ok := ctx["identityProviders"].([]map[string]any); ok {
		ctx["hasIdentityProviders"] = len(providers) > 0
	} else {
		ctx["hasIdentityProviders"] = false
	}

	enrichClients(ctx)
	enrichUsers(ctx)
	enrichClientCreated(ctx)
	enrichClientForm(ctx)
	enrichUserForm(ctx)
	enrichProfile(ctx)
}

func enrichProfile(ctx map[string]any) {
	if _, ok := ctx["profileNameValue"]; ok {
		return
	}
	if user, ok := ctx["user"].(map[string]any); ok {
		if name, ok := user["name"].(string); ok {
			ctx["profileNameValue"] = name
		}
	}
}

func enrichClients(ctx map[string]any) {
	raw, ok := ctx["clients"]
	if !ok {
		return
	}
	var clients []model.OAuthClient
	switch v := raw.(type) {
	case []model.OAuthClient:
		clients = v
	default:
		return
	}
	basePath, _ := ctx["basePath"].(string)
	lang, _ := ctx["lang"].(string)
	msgs, _ := ctx["_messages"].(*i18n.Messages)
	rows := make([]map[string]any, 0, len(clients))
	for _, c := range clients {
		confirm := "Delete " + c.ClientID + "?"
		if msgs != nil {
			confirm = msgs.Get(lang, "admin.clients.confirmDelete", c.ClientID)
		}
		rows = append(rows, map[string]any{
			"clientId":      c.ClientID,
			"displayName":   c.DisplayName,
			"displayLabel":  c.DisplayLabel(),
			"redirectUri":   c.RedirectURI,
			"theme":         c.Theme,
			"themeLabel":    themeLabel(c.Theme),
			"confidential":  c.IsConfidential(),
			"confirmDelete": confirm,
			"editHref":      basePath + "/admin/clients/" + url.PathEscape(c.ClientID) + "/edit",
		})
	}
	ctx["clientRows"] = rows
	ctx["hasClientRows"] = len(rows) > 0
}

func themeLabel(theme string) string {
	theme = strings.TrimSpace(theme)
	if theme == "" {
		return "—"
	}
	return theme
}

func enrichUsers(ctx map[string]any) {
	raw, ok := ctx["users"]
	if !ok {
		return
	}
	var users []model.User
	switch v := raw.(type) {
	case []model.User:
		users = v
	default:
		return
	}
	basePath, _ := ctx["basePath"].(string)
	lang, _ := ctx["lang"].(string)
	msgs, _ := ctx["_messages"].(*i18n.Messages)
	rows := make([]map[string]any, 0, len(users))
	for _, u := range users {
		confirmDelete := "Delete " + u.Email + "?"
		confirm2fa := "Remove 2FA for " + u.Email + "?"
		confirmResend := "Resend verification email to " + u.Email + "?"
		if msgs != nil {
			confirmDelete = msgs.Get(lang, "admin.users.confirmDelete", u.Email)
			confirm2fa = msgs.Get(lang, "admin.users.confirmRemove2fa", u.Email)
			confirmResend = msgs.Get(lang, "admin.users.confirmResendVerification", u.Email)
		}
		name := u.Name
		if name == "" {
			name = "—"
		}
		rows = append(rows, map[string]any{
			"id":                    u.ID,
			"email":                 u.Email,
			"name":                  name,
			"adminType":             u.IsAdmin(),
			"emailVerified":         u.IsEmailVerified(),
			"totpEnabled":           u.IsTotpEnabled(),
			"canResendVerification": !u.IsEmailVerified() && u.HasLocalPassword(),
			"editHref":              basePath + "/admin/users/edit?userId=" + url.QueryEscape(u.ID),
			"confirmDelete":         confirmDelete,
			"confirmRemove2fa":      confirm2fa,
			"confirmResend":         confirmResend,
		})
	}
	ctx["userRows"] = rows
	ctx["hasUserRows"] = len(rows) > 0
}

func enrichClientCreated(ctx map[string]any) {
	switch c := ctx["client"].(type) {
	case *model.OAuthClient:
		ctx["client"] = map[string]any{
			"clientId":     c.ClientID,
			"displayName":  c.DisplayName,
			"redirectUri":  c.RedirectURI,
			"clientSecret": c.ClientSecret,
			"theme":        c.Theme,
		}
		ctx["clientConfidential"] = c.IsConfidential()
	case model.OAuthClient:
		ctx["client"] = map[string]any{
			"clientId":     c.ClientID,
			"displayName":  c.DisplayName,
			"redirectUri":  c.RedirectURI,
			"clientSecret": c.ClientSecret,
			"theme":        c.Theme,
		}
		ctx["clientConfidential"] = c.IsConfidential()
	case map[string]any:
		secret, _ := c["clientSecret"].(string)
		ctx["clientConfidential"] = secret != ""
	}
}

func enrichClientForm(ctx map[string]any) {
	if _, ok := ctx["formClientIdValue"]; !ok {
		if v, ok := ctx["formClientId"].(string); ok {
			ctx["formClientIdValue"] = v
		} else {
			ctx["formClientIdValue"] = ""
		}
	}
	if _, ok := ctx["formDisplayNameValue"]; !ok {
		if v, ok := ctx["formDisplayName"].(string); ok {
			ctx["formDisplayNameValue"] = v
		} else {
			ctx["formDisplayNameValue"] = ""
		}
	}
	if _, ok := ctx["formRedirectUriValue"]; !ok {
		if v, ok := ctx["formRedirectUri"].(string); ok {
			ctx["formRedirectUriValue"] = v
		} else {
			ctx["formRedirectUriValue"] = ""
		}
	}
	if _, ok := ctx["formTheme"]; !ok {
		ctx["formTheme"] = ""
	}
	editing, _ := ctx["editingClient"].(bool)
	ctx["editingClient"] = editing
	if editing {
		ctx["clientIdReadonly"] = true
	}
}

func enrichUserForm(ctx map[string]any) {
	edit, editing := ctx["editUser"].(*model.User)
	if !editing {
		if u, ok := ctx["editUser"].(model.User); ok {
			edit = &u
			editing = true
		}
	}
	ctx["editing"] = editing
	formType, _ := ctx["formType"].(string)
	ctx["typeUserSelected"] = formType == "" || formType == model.TypeUser
	ctx["typeAdminSelected"] = formType == model.TypeAdmin
	if v, ok := ctx["formAction"].(string); ok && v != "" {
		ctx["formActionPath"] = v
	} else {
		ctx["formActionPath"] = "/admin/users"
	}
	if v, ok := ctx["formEmail"].(string); ok {
		ctx["formEmailValue"] = v
	} else {
		ctx["formEmailValue"] = ""
	}
	if v, ok := ctx["formName"].(string); ok {
		ctx["formNameValue"] = v
	} else {
		ctx["formNameValue"] = ""
	}
	ctx["passwordRequired"] = !editing
	lang, _ := ctx["lang"].(string)
	msgs, _ := ctx["_messages"].(*i18n.Messages)
	if editing && edit != nil {
		ctx["editUserId"] = edit.ID
		ctx["editUserIdEncoded"] = url.QueryEscape(edit.ID)
		ctx["showEmailVerified"] = edit.HasLocalPassword()
		ctx["totpEnabled"] = edit.IsTotpEnabled()
		if v, ok := ctx["formEmailVerified"].(bool); ok {
			ctx["emailVerifiedChecked"] = v
		} else {
			ctx["emailVerifiedChecked"] = edit.IsEmailVerified()
		}
		if msgs != nil {
			ctx["passwordLabel"] = msgs.Get(lang, "admin.userForm.password") + " " + msgs.Get(lang, "admin.userForm.passwordOptional")
			ctx["passwordPlaceholder"] = msgs.Get(lang, "admin.userForm.passwordKeep")
			ctx["headerTitle"] = msgs.Get(lang, "admin.userForm.editHeading")
			ctx["headerHelp"] = msgs.Get(lang, "admin.userForm.editHint", edit.ID)
			ctx["submitLabel"] = msgs.Get(lang, "admin.userForm.save")
			ctx["confirmRemove2fa"] = msgs.Get(lang, "admin.userForm.confirmRemove2fa")
		}
	} else if msgs != nil {
		ctx["passwordLabel"] = msgs.Get(lang, "admin.userForm.password")
		ctx["passwordPlaceholder"] = msgs.Get(lang, "password.placeholder")
		ctx["headerTitle"] = msgs.Get(lang, "admin.userForm.newHeading")
		ctx["headerHelp"] = msgs.Get(lang, "admin.userForm.newHint")
		ctx["submitLabel"] = msgs.Get(lang, "admin.userForm.create")
	}
}

func isAuthPage(base string) bool {
	switch base {
	case "login", "login2fa", "register", "registerPending", "emailNotVerified", "consent", "verifyEmailSuccess", "verifyEmailError":
		return true
	default:
		return false
	}
}

func layoutFor(name string) string {
	base := stripExt(name)
	if strings.HasPrefix(base, "email/") {
		return ""
	}
	if strings.HasPrefix(base, "admin/") {
		return "adminLayout.mustache"
	}
	return "layout.mustache"
}

func normalize(template string) string {
	name := strings.TrimPrefix(template, "/")
	if strings.HasSuffix(name, ".jte") {
		name = strings.TrimSuffix(name, ".jte") + ".mustache"
	} else if !strings.HasSuffix(name, ".mustache") {
		name += ".mustache"
	}
	return name
}

func stripExt(name string) string {
	return strings.TrimSuffix(name, ".mustache")
}

func formatMessage(messages *i18n.Messages, lang, body string) string {
	text := strings.TrimSpace(body)
	if text == "" {
		return ""
	}
	parts := strings.Split(text, "|")
	key := strings.TrimSpace(parts[0])
	if len(parts) == 1 {
		return messages.Get(lang, key)
	}
	args := make([]any, 0, len(parts)-1)
	for i := 1; i < len(parts); i++ {
		args = append(args, parts[i])
	}
	return messages.Get(lang, key, args...)
}

// StaticFS returns the embedded static file tree rooted at "static".
func StaticFS() (fs.FS, error) {
	return fs.Sub(web.FS, "static")
}
