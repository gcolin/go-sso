package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gcolin/go-sso/internal/model"
	"github.com/gcolin/go-sso/internal/oauth"
	"github.com/gcolin/go-sso/internal/runtime"
	"github.com/gcolin/go-sso/internal/security"
)

type Server struct {
	rt *runtime.Runtime
}

func New(rt *runtime.Runtime) *Server {
	return &Server{rt: rt}
}

func (s *Server) Handler() http.Handler {
	mux := s.routes()
	ctxPath := s.contextPath()
	if ctxPath == "" {
		return mux
	}
	outer := http.NewServeMux()
	outer.Handle(ctxPath+"/", http.StripPrefix(ctxPath, mux))
	outer.HandleFunc("GET "+ctxPath, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ctxPath+"/", http.StatusFound)
	})
	outer.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ctxPath+"/", http.StatusFound)
	})
	return outer
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("POST /api/auth/login", s.login)
	mux.HandleFunc("POST /api/auth/2fa/verify", s.verify2fa)
	mux.HandleFunc("POST /api/auth/logout", s.logout)
	mux.HandleFunc("GET /api/me", s.me)

	mux.HandleFunc("GET /api/admin/users", s.adminListUsers)
	mux.HandleFunc("POST /api/admin/users", s.adminCreateUser)
	mux.HandleFunc("PUT /api/admin/users/{userId}", s.adminUpdateUser)
	mux.HandleFunc("DELETE /api/admin/users/{userId}", s.adminDeleteUser)
	mux.HandleFunc("DELETE /api/admin/users/{userId}/totp", s.adminDisableTotp)

	mux.HandleFunc("GET /api/admin/oauth/clients", s.adminListClients)
	mux.HandleFunc("POST /api/admin/oauth/clients", s.adminCreateClient)
	mux.HandleFunc("PUT /api/admin/oauth/clients/{clientId}", s.adminUpdateClient)
	mux.HandleFunc("DELETE /api/admin/oauth/clients/{clientId}", s.adminDeleteClient)

	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.discovery)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /.well-known/jwks.json", s.jwks)

	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("GET /oauth/userinfo", s.userinfo)
	mux.HandleFunc("GET /oauth/logout", s.oauthLogout)
	mux.HandleFunc("POST /oauth/authorize/decision", s.authorizeDecision)
	mux.HandleFunc("GET /oauth/authorize", s.authorize)

	mux.HandleFunc("GET /auth/external/{providerId}", s.externalLogin)
	mux.HandleFunc("GET /auth/callback/{providerId}", s.externalCallback)
	mux.HandleFunc("GET /realms/{realm}/broker/{providerId}/endpoint", s.externalCallbackRealm)

	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.loginFormSubmit)
	mux.HandleFunc("GET /login/2fa", s.login2faPage)
	mux.HandleFunc("POST /login/2fa", s.login2faSubmit)
	mux.HandleFunc("GET /login/unverified", s.loginUnverifiedPage)
	mux.HandleFunc("GET /register", s.registerForm)
	mux.HandleFunc("POST /register", s.registerSubmit)
	mux.HandleFunc("GET /register/pending", s.registerPendingForm)
	mux.HandleFunc("POST /register/pending", s.registerPendingSubmit)
	mux.HandleFunc("GET /verify-email", s.verifyEmailPage)
	mux.HandleFunc("POST /verify-email/resend", s.resendVerificationEmail)
	mux.HandleFunc("POST /logout", s.logoutHTML)

	mux.HandleFunc("GET /profile", s.profilePage)
	mux.HandleFunc("POST /profile", s.profileUpdate)
	mux.HandleFunc("GET /profile/password", s.changePasswordPage)
	mux.HandleFunc("POST /profile/password", s.changePasswordUpdate)
	mux.HandleFunc("POST /profile/password/remove", s.removePassword)
	mux.HandleFunc("GET /profile/2fa", s.profile2faPage)
	mux.HandleFunc("POST /profile/2fa/setup", s.profile2faSetup)
	mux.HandleFunc("POST /profile/2fa/confirm", s.profile2faConfirm)
	mux.HandleFunc("POST /profile/2fa/disable", s.profile2faDisable)

	mux.HandleFunc("GET /admin", s.adminRoot)
	mux.HandleFunc("GET /admin/clients", s.adminClientsPage)
	mux.HandleFunc("GET /admin/clients/new", s.adminClientFormPage)
	mux.HandleFunc("POST /admin/clients", s.adminClientCreatePage)
	mux.HandleFunc("GET /admin/clients/{clientId}/edit", s.adminClientEditPage)
	mux.HandleFunc("POST /admin/clients/{clientId}", s.adminClientUpdatePage)
	mux.HandleFunc("POST /admin/clients/delete", s.adminClientDeletePage)
	mux.HandleFunc("GET /admin/users", s.adminUsersPage)
	mux.HandleFunc("GET /admin/users/new", s.adminUserFormPage)
	mux.HandleFunc("GET /admin/users/edit", s.adminUserEditPage)
	mux.HandleFunc("POST /admin/users", s.adminUserCreatePage)
	mux.HandleFunc("POST /admin/users/update", s.adminUserUpdatePage)
	mux.HandleFunc("POST /admin/users/delete", s.adminUserDeletePage)
	mux.HandleFunc("POST /admin/users/disable-2fa", s.adminUserDisable2faPage)
	mux.HandleFunc("POST /admin/users/resend-verification", s.adminUserResendVerification)

	mux.HandleFunc("GET /admin/settings", s.adminSettingsRoot)
	mux.HandleFunc("GET /admin/settings/server", s.adminSettingsServerPage)
	mux.HandleFunc("POST /admin/settings/server", s.adminSettingsServerUpdate)
	mux.HandleFunc("GET /admin/settings/security", s.adminSettingsSecurityPage)
	mux.HandleFunc("POST /admin/settings/security", s.adminSettingsSecurityUpdate)
	mux.HandleFunc("GET /admin/settings/federation", s.adminSettingsFederationPage)
	mux.HandleFunc("POST /admin/settings/federation", s.adminSettingsFederationUpdate)
	mux.HandleFunc("POST /admin/settings/federation/providers", s.adminSettingsFederationProviderCreate)
	mux.HandleFunc("GET /admin/settings/federation/providers/edit", s.adminSettingsFederationProviderEditPage)
	mux.HandleFunc("POST /admin/settings/federation/providers/update", s.adminSettingsFederationProviderUpdate)
	mux.HandleFunc("POST /admin/settings/federation/providers/delete", s.adminSettingsFederationProviderDelete)
	mux.HandleFunc("GET /admin/settings/mail", s.adminSettingsMailPage)
	mux.HandleFunc("POST /admin/settings/mail", s.adminSettingsMailUpdate)

	mux.Handle("GET /static/", s.serveStatic())
	mux.HandleFunc("GET /themes/{theme}/static/{path...}", s.serveThemeStatic)

	return mux
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, msg("error", "invalid json"))
		return
	}
	if retry := s.rt.RateLimit.CheckAndRecord(clientIP(r)); retry > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retry))
		writeJSON(w, http.StatusTooManyRequests, msg("error", "too many login attempts"))
		return
	}
	if strings.TrimSpace(req.Email) == "" || strings.TrimSpace(req.Password) == "" {
		writeJSON(w, http.StatusBadRequest, msg("error", "email and password are required"))
		return
	}
	switch s.rt.Passwords.AuthenticateStatus(req.Email, req.Password) {
	case security.AuthInvalidCredentials:
		writeJSON(w, http.StatusUnauthorized, msg("error", "invalid credentials"))
		return
	case security.AuthEmailNotVerified:
		writeJSON(w, http.StatusForbidden, msg("error", "email not verified"))
		return
	}
	user := s.rt.Passwords.Authenticate(req.Email, req.Password)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, msg("error", "invalid credentials"))
		return
	}
	if user.IsTotpEnabled() {
		pending, err := s.rt.Sessions.CreatePending2FAToken(user, "/")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, msg("error", "internal error"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "2fa_required", "pendingToken": pending})
		return
	}
	if err := s.rt.Sessions.WriteSession(w, user); err != nil {
		writeJSON(w, http.StatusInternalServerError, msg("error", "internal error"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "user": userSummary(user)})
}

func (s *Server) verify2fa(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PendingToken string `json:"pendingToken"`
		Code         string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil || strings.TrimSpace(req.PendingToken) == "" || strings.TrimSpace(req.Code) == "" {
		writeJSON(w, http.StatusBadRequest, msg("error", "pendingToken and code are required"))
		return
	}
	pending, err := s.rt.JWT.ParsePending2FAToken(req.PendingToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, msg("error", "invalid or expired pending token"))
		return
	}
	if retry := s.rt.RateLimit.CheckAndRecord("2fa:" + clientIP(r) + ":" + pending.UserID); retry > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retry))
		writeJSON(w, http.StatusTooManyRequests, msg("error", "too many 2fa attempts"))
		return
	}
	ok, verr := s.rt.UserReg.VerifyTotpLogin(pending.UserID, req.Code)
	if verr != nil {
		writeJSON(w, http.StatusBadRequest, msg("error", verr.Error()))
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, msg("error", "invalid code"))
		return
	}
	user, found := s.rt.UserReg.FindByID(pending.UserID)
	if !found {
		writeJSON(w, http.StatusUnauthorized, msg("error", "user not found"))
		return
	}
	if err := s.rt.Sessions.WriteSession(w, user); err != nil {
		writeJSON(w, http.StatusInternalServerError, msg("error", "internal error"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "user": userSummary(user)})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.rt.Sessions.ClearSession(w)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "logged out"})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	user := s.rt.Sessions.CurrentUser(r)
	if user == nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": userSummary(user)})
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) *model.User {
	user := s.rt.Sessions.CurrentUser(r)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, msg("error", "authentication required"))
		return nil
	}
	if !user.IsAdmin() {
		writeJSON(w, http.StatusForbidden, msg("error", "admin required"))
		return nil
	}
	return user
}

func (s *Server) adminListUsers(w http.ResponseWriter, r *http.Request) {
	if s.requireAdmin(w, r) == nil {
		return
	}
	users := s.rt.UserReg.List()
	out := make([]map[string]any, 0, len(users))
	for i := range users {
		out = append(out, adminUserSummary(&users[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	if s.requireAdmin(w, r) == nil {
		return
	}
	var req struct {
		Email           string `json:"email"`
		Name            string `json:"name"`
		Type            string `json:"type"`
		Password        string `json:"password"`
		MaxStorageBytes int64  `json:"maxStorageBytes"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, msg("error", "invalid json"))
		return
	}
	u, err := s.rt.UserReg.Create(req.Email, req.Name, req.Type, req.Password, req.MaxStorageBytes)
	if err != nil {
		writeDomainErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"status": "ok", "user": adminUserSummary(u)})
}

func (s *Server) adminUpdateUser(w http.ResponseWriter, r *http.Request) {
	if s.requireAdmin(w, r) == nil {
		return
	}
	var req struct {
		Email           *string `json:"email"`
		Name            *string `json:"name"`
		Type            *string `json:"type"`
		Password        *string `json:"password"`
		EmailVerified   *bool   `json:"emailVerified"`
		MaxStorageBytes *int64  `json:"maxStorageBytes"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, msg("error", "invalid json"))
		return
	}
	email, name, typ, password := "", "", "", ""
	if req.Email != nil {
		email = *req.Email
	}
	if req.Name != nil {
		name = *req.Name
	}
	if req.Type != nil {
		typ = *req.Type
	}
	if req.Password != nil {
		password = *req.Password
	}
	u, err := s.rt.UserReg.Update(r.PathValue("userId"), email, name, typ, password, req.EmailVerified, req.MaxStorageBytes)
	if err != nil {
		writeDomainErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "user": adminUserSummary(u)})
}

func (s *Server) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	if s.requireAdmin(w, r) == nil {
		return
	}
	if err := s.rt.UserReg.Delete(r.PathValue("userId")); err != nil {
		writeDomainErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "user deleted"})
}

func (s *Server) adminDisableTotp(w http.ResponseWriter, r *http.Request) {
	if s.requireAdmin(w, r) == nil {
		return
	}
	if err := s.rt.UserReg.DisableTotp(r.PathValue("userId")); err != nil {
		writeDomainErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "totp disabled"})
}

func (s *Server) adminListClients(w http.ResponseWriter, r *http.Request) {
	if s.requireAdmin(w, r) == nil {
		return
	}
	clients := s.rt.Clients.ListAll()
	out := make([]map[string]any, 0, len(clients))
	for _, c := range clients {
		out = append(out, map[string]any{
			"clientId":     c.ClientID,
			"displayName":  c.DisplayName,
			"label":        c.DisplayLabel(),
			"redirectUri":  c.RedirectURI,
			"theme":        c.Theme,
			"confidential": c.IsConfidential(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": out})
}

func (s *Server) adminCreateClient(w http.ResponseWriter, r *http.Request) {
	if s.requireAdmin(w, r) == nil {
		return
	}
	var req struct {
		ClientID     string `json:"clientId"`
		DisplayName  string `json:"displayName"`
		RedirectURI  string `json:"redirectUri"`
		Theme        string `json:"theme"`
		Confidential bool   `json:"confidential"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, msg("error", "invalid json"))
		return
	}
	if err := s.validateClientTheme(req.Theme); err != nil {
		writeJSON(w, http.StatusBadRequest, msg("error", err.Error()))
		return
	}
	c, err := s.rt.Clients.Create(req.ClientID, req.DisplayName, req.RedirectURI, req.Theme, req.Confidential)
	if err != nil {
		writeDomainErr(w, err)
		return
	}
	body := map[string]any{
		"clientId":     c.ClientID,
		"displayName":  c.DisplayName,
		"redirectUri":  c.RedirectURI,
		"theme":        c.Theme,
		"confidential": c.IsConfidential(),
	}
	if c.ClientSecret != "" {
		body["clientSecret"] = c.ClientSecret
	}
	writeJSON(w, http.StatusCreated, map[string]any{"status": "ok", "client": body})
}

func (s *Server) adminUpdateClient(w http.ResponseWriter, r *http.Request) {
	if s.requireAdmin(w, r) == nil {
		return
	}
	var req struct {
		DisplayName string `json:"displayName"`
		RedirectURI string `json:"redirectUri"`
		Theme       string `json:"theme"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, msg("error", "invalid json"))
		return
	}
	if err := s.validateClientTheme(req.Theme); err != nil {
		writeJSON(w, http.StatusBadRequest, msg("error", err.Error()))
		return
	}
	c, err := s.rt.Clients.Update(r.PathValue("clientId"), req.DisplayName, req.RedirectURI, req.Theme)
	if err != nil {
		writeDomainErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"client": map[string]any{
			"clientId":     c.ClientID,
			"displayName":  c.DisplayName,
			"redirectUri":  c.RedirectURI,
			"theme":        c.Theme,
			"confidential": c.IsConfidential(),
		},
	})
}

func (s *Server) adminDeleteClient(w http.ResponseWriter, r *http.Request) {
	if s.requireAdmin(w, r) == nil {
		return
	}
	if err := s.rt.Clients.Delete(r.PathValue("clientId")); err != nil {
		writeDomainErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "deleted"})
}

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.rt.OAuth.DiscoveryDocument())
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.rt.OAuth.JWKSDocument())
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	req, err := parseTokenRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	res := s.rt.OAuth.ExchangeToken(req)
	if !res.OK {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": res.Error})
		return
	}
	body := map[string]any{
		"access_token": res.AccessToken,
		"token_type":   "Bearer",
		"expires_in":   res.ExpiresIn,
	}
	if res.Scope != "" {
		body["scope"] = res.Scope
	}
	if res.IDToken != "" {
		body["id_token"] = res.IDToken
	}
	writeJSON(w, http.StatusOK, body)
}

func parseTokenRequest(r *http.Request) (oauth.TokenRequest, error) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(strings.ToLower(ct), "application/json") {
		var body struct {
			GrantType    string `json:"grant_type"`
			Code         string `json:"code"`
			RedirectURI  string `json:"redirect_uri"`
			ClientID     string `json:"client_id"`
			CodeVerifier string `json:"code_verifier"`
			ClientSecret string `json:"client_secret"`
			Scope        string `json:"scope"`
		}
		if err := readJSON(r, &body); err != nil {
			return oauth.TokenRequest{}, err
		}
		req := oauth.TokenRequest{
			GrantType: body.GrantType, Code: body.Code, RedirectURI: body.RedirectURI,
			ClientID: body.ClientID, CodeVerifier: body.CodeVerifier,
			ClientSecret: body.ClientSecret, Scope: body.Scope,
		}
		applyBasicAuth(&req, r.Header.Get("Authorization"))
		return req, nil
	}
	if err := r.ParseForm(); err != nil {
		return oauth.TokenRequest{}, err
	}
	req := oauth.TokenRequest{
		GrantType: r.Form.Get("grant_type"), Code: r.Form.Get("code"),
		RedirectURI: r.Form.Get("redirect_uri"), ClientID: r.Form.Get("client_id"),
		CodeVerifier: r.Form.Get("code_verifier"), ClientSecret: r.Form.Get("client_secret"),
		Scope: r.Form.Get("scope"),
	}
	applyBasicAuth(&req, r.Header.Get("Authorization"))
	return req, nil
}

func applyBasicAuth(req *oauth.TokenRequest, auth string) {
	if !strings.HasPrefix(strings.ToLower(auth), "basic ") {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[6:]))
	if err != nil {
		return
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return
	}
	if req.ClientID == "" {
		req.ClientID = parts[0]
	}
	if req.ClientSecret == "" {
		req.ClientSecret = parts[1]
	}
}

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	info, ok := s.rt.OAuth.UserInfo(r.Header.Get("Authorization"))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) authorizeDecision(w http.ResponseWriter, r *http.Request) {
	if !s.requireCSRF(w, r) {
		return
	}
	user := s.rt.Sessions.CurrentUser(r)
	if user == nil {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	allow := r.Form.Get("decision") == "allow" || r.Form.Get("decision") == "approve"
	requestID := r.Form.Get("request_id")
	req, ok := s.rt.AuthRequests.Peek(requestID)
	if !ok {
		http.Error(w, "error.oauth.requestExpired", http.StatusBadRequest)
		return
	}
	if req.UserID != user.ID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.rememberSessionClient(w, r, req.ClientID)
	res := s.rt.OAuth.HandleDecision(requestID, allow)
	if !res.OK {
		http.Error(w, res.Message, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, res.RedirectURL, http.StatusFound)
}

func userSummary(u *model.User) map[string]any {
	return map[string]any{
		"id": u.ID, "email": u.Email, "name": u.Name, "type": u.AccountType(),
		"roles": u.PlatformRoles(), "emailVerified": u.IsEmailVerified(),
	}
}

func adminUserSummary(u *model.User) map[string]any {
	m := userSummary(u)
	m["totpEnabled"] = u.IsTotpEnabled()
	m["maxStorageBytes"] = u.MaxStorageBytes
	return m
}

func writeDomainErr(w http.ResponseWriter, err error) {
	var unf *security.UserNotFoundError
	var ucf *security.UserConflictError
	var uv *security.UserValidationError
	var cnf *oauth.ClientNotFoundError
	var ccf *oauth.ClientConflictError
	var cv *oauth.ClientValidationError
	switch {
	case errors.As(err, &unf):
		writeJSON(w, http.StatusNotFound, msg("error", unf.Error()))
	case errors.As(err, &cnf):
		writeJSON(w, http.StatusNotFound, msg("error", cnf.Error()))
	case errors.As(err, &ucf):
		writeJSON(w, http.StatusConflict, msg("error", ucf.Error()))
	case errors.As(err, &ccf):
		writeJSON(w, http.StatusConflict, msg("error", ccf.Error()))
	case errors.As(err, &uv):
		writeJSON(w, http.StatusBadRequest, msg("error", uv.Error()))
	case errors.As(err, &cv):
		writeJSON(w, http.StatusBadRequest, msg("error", cv.Error()))
	default:
		writeJSON(w, http.StatusBadRequest, msg("error", err.Error()))
	}
}

func msg(status, message string) map[string]string {
	return map[string]string{"status": status, "message": message}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(dst)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
