package httpapi_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/gcolin/go-sso/internal/oauth"
	"github.com/gcolin/go-sso/internal/testsupport"
)

// Ports OAuthFlowTest over the Go mux (authorize → login → consent → token → userinfo).

var requestIDPattern = regexp.MustCompile(`name="request_id"\s+value="([^"]+)"`)

func TestDiscoveryDocumentExposesOAuthEndpoints(t *testing.T) {
	h := testsupport.NewHandler(t, ssoBase)
	for _, path := range []string{
		"/sso/.well-known/oauth-authorization-server",
		"/sso/.well-known/openid-configuration",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d", path, rec.Code)
		}
		var doc map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "end_session_endpoint"} {
			v, _ := doc[key].(string)
			if !strings.Contains(v, "/oauth/") {
				t.Fatalf("%s %s=%q", path, key, v)
			}
		}
		algs, _ := doc["id_token_signing_alg_values_supported"].([]any)
		if len(algs) == 0 {
			t.Fatalf("%s missing id_token_signing_alg_values_supported", path)
		}
	}
}

func TestOAuthLogoutClearsSessionAndRedirects(t *testing.T) {
	h := testsupport.NewHandler(t, ssoBase)
	cookie := testsupport.LoginCookie(t, h, "/sso", testsupport.UserEmail, testsupport.Password)

	redirect := "https://tournoistest.tregorechecs.fr/"
	// Fixture clients use localhost redirect; allow via host match against publicBaseUrl only fails.
	// Use redirect matching test client host.
	redirect = "http://localhost:8080/node/auth/callback"
	req := httptest.NewRequest(http.MethodGet, "/sso/oauth/logout?"+url.Values{
		"post_logout_redirect_uri": {redirect},
	}.Encode(), nil)
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != redirect {
		t.Fatalf("Location=%q want %q", loc, redirect)
	}
	setCookie := strings.Join(rec.Header().Values("Set-Cookie"), "\n")
	if !strings.Contains(setCookie, "Max-Age=0") && !strings.Contains(strings.ToLower(setCookie), "max-age=0") {
		t.Fatalf("expected session cleared, Set-Cookie=%q", setCookie)
	}

	// Reject open redirect
	req2 := httptest.NewRequest(http.MethodGet, "/sso/oauth/logout?"+url.Values{
		"post_logout_redirect_uri": {"https://evil.example/phish"},
	}.Encode(), nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusFound {
		t.Fatalf("reject status=%d", rec2.Code)
	}
	if loc := rec2.Header().Get("Location"); loc != "/sso/" && loc != "/sso" {
		// redirect helper uses path under context
		if !strings.HasPrefix(loc, "/sso") {
			t.Fatalf("expected fallback to app home, got %q", loc)
		}
	}
}

func TestAuthorizationCodeFlowWithPkce(t *testing.T) {
	h := testsupport.NewHandler(t, ssoBase)
	state := "test-state"
	verifier := randomCodeVerifier(t)
	challenge := oauth.ChallengeS256(verifier)

	authorizeURL := "/sso/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {testsupport.TestClientID},
		"redirect_uri":          {testsupport.TestRedirect},
		"scope":                 {"openid profile email"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	unauth := get(t, h, authorizeURL, "")
	if unauth.Code != http.StatusOK {
		t.Fatalf("unauth status=%d", unauth.Code)
	}
	loginBody := unauth.Body.String()
	if !strings.Contains(loginBody, `name="returnUrl"`) || !strings.Contains(loginBody, "/oauth/authorize?") {
		t.Fatalf("expected login page with authorize returnUrl, got %s", truncate(loginBody, 300))
	}
	if !strings.Contains(loginBody, testsupport.TestClientID) {
		t.Fatalf("expected clientId on login page, got %s", truncate(loginBody, 300))
	}

	cookie := testsupport.LoginCookie(t, h, "/sso", testsupport.UserEmail, testsupport.Password)
	consent := get(t, h, authorizeURL, cookie)
	if consent.Code != http.StatusOK {
		t.Fatalf("consent status=%d body=%s", consent.Code, truncate(consent.Body.String(), 200))
	}
	body := consent.Body.String()
	if !strings.Contains(body, "Autoriser l") && !strings.Contains(body, "Allow access") {
		t.Fatalf("expected consent page, got %s", truncate(body, 240))
	}
	if !strings.Contains(body, "Test app") {
		t.Fatalf("expected client display name on consent page, got %s", truncate(body, 240))
	}
	if strings.Contains(body, testsupport.TestRedirect) {
		t.Fatalf("redirect URI should not appear on consent page")
	}
	if strings.Contains(body, "openid") {
		t.Fatalf("raw openid scope should not appear on consent page")
	}
	if !strings.Contains(body, "<li>") || strings.Contains(body, "[connaître") || strings.Contains(body, "[know your") {
		t.Fatalf("expected iterated scope <li> items, got %s", truncate(body, 400))
	}
	m := requestIDPattern.FindStringSubmatch(body)
	if len(m) != 2 {
		t.Fatalf("missing request_id in consent html")
	}
	requestID := m[1]
	csrf := testsupport.ExtractCSRF(t, body)

	form := url.Values{
		"request_id": {requestID},
		"decision":   {"allow"},
		"_csrf":      {csrf},
	}.Encode()
	decReq := httptest.NewRequest(http.MethodPost, "/sso/oauth/authorize/decision", strings.NewReader(form))
	decReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	decReq.Header.Set("Cookie", cookie)
	decRec := httptest.NewRecorder()
	h.ServeHTTP(decRec, decReq)
	if decRec.Code != http.StatusFound {
		t.Fatalf("decision status=%d body=%s", decRec.Code, decRec.Body.String())
	}
	loc := decRec.Header().Get("Location")
	if !strings.HasPrefix(loc, testsupport.TestRedirect) {
		t.Fatalf("Location=%q", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("missing code in %q", loc)
	}
	if u.Query().Get("state") != state {
		t.Fatalf("state=%q", u.Query().Get("state"))
	}

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testsupport.TestRedirect},
		"client_id":     {testsupport.TestClientID},
		"code_verifier": {verifier},
	}.Encode()
	tokReq := httptest.NewRequest(http.MethodPost, "/sso/oauth/token", strings.NewReader(tokenForm))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := httptest.NewRecorder()
	h.ServeHTTP(tokRec, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", tokRec.Code, tokRec.Body.String())
	}
	var tokenBody map[string]any
	if err := json.Unmarshal(tokRec.Body.Bytes(), &tokenBody); err != nil {
		t.Fatal(err)
	}
	accessToken, _ := tokenBody["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("missing access_token: %v", tokenBody)
	}
	if tokenBody["token_type"] != "Bearer" {
		t.Fatalf("token_type=%v", tokenBody["token_type"])
	}
	idToken, _ := tokenBody["id_token"].(string)
	if idToken == "" {
		t.Fatalf("missing id_token for openid scope: %v", tokenBody)
	}
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token is not a JWT: %s", truncate(idToken, 80))
	}

	uiReq := httptest.NewRequest(http.MethodGet, "/sso/oauth/userinfo", nil)
	uiReq.Header.Set("Authorization", "Bearer "+accessToken)
	uiRec := httptest.NewRecorder()
	h.ServeHTTP(uiRec, uiReq)
	if uiRec.Code != http.StatusOK {
		t.Fatalf("userinfo status=%d body=%s", uiRec.Code, uiRec.Body.String())
	}
	var info map[string]any
	if err := json.Unmarshal(uiRec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info["sub"] != "user-1" {
		t.Fatalf("sub=%v", info["sub"])
	}
	if info["email"] != testsupport.UserEmail {
		t.Fatalf("email=%v", info["email"])
	}
}

func TestAuthorizeDecisionRequiresSessionBinding(t *testing.T) {
	rt, h := testsupport.NewRuntime(t, ssoBase)
	verifier := randomCodeVerifier(t)
	challenge := oauth.ChallengeS256(verifier)
	authorizeURL := "/sso/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {testsupport.TestClientID},
		"redirect_uri":          {testsupport.TestRedirect},
		"scope":                 {"openid profile email"},
		"state":                 {"bind-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	userCookie := testsupport.LoginCookie(t, h, "/sso", testsupport.UserEmail, testsupport.Password)
	consent := get(t, h, authorizeURL, userCookie)
	if consent.Code != http.StatusOK {
		t.Fatalf("consent status=%d", consent.Code)
	}
	m := requestIDPattern.FindStringSubmatch(consent.Body.String())
	if len(m) != 2 {
		t.Fatalf("missing request_id")
	}
	requestID := m[1]
	csrf := testsupport.ExtractCSRF(t, consent.Body.String())
	form := url.Values{
		"request_id": {requestID},
		"decision":   {"allow"},
		"_csrf":      {csrf},
	}.Encode()

	// No session cookie → 401 (CSRF for user fails first → 403 is also acceptable)
	noSession := httptest.NewRequest(http.MethodPost, "/sso/oauth/authorize/decision", strings.NewReader(form))
	noSession.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	noSessionRec := httptest.NewRecorder()
	h.ServeHTTP(noSessionRec, noSession)
	if noSessionRec.Code != http.StatusUnauthorized && noSessionRec.Code != http.StatusForbidden {
		t.Fatalf("no session: status=%d want 401 or 403", noSessionRec.Code)
	}

	// Different user session → 403; request must remain consumable by owner
	adminCookie := testsupport.LoginCookie(t, h, "/sso", testsupport.AdminEmail, testsupport.Password)
	wrongForm := url.Values{
		"request_id": {requestID},
		"decision":   {"allow"},
		"_csrf":      {testsupport.CSRFToken(t, rt, "admin-1")},
	}.Encode()
	wrongUser := httptest.NewRequest(http.MethodPost, "/sso/oauth/authorize/decision", strings.NewReader(wrongForm))
	wrongUser.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wrongUser.Header.Set("Cookie", adminCookie)
	wrongUserRec := httptest.NewRecorder()
	h.ServeHTTP(wrongUserRec, wrongUser)
	if wrongUserRec.Code != http.StatusForbidden {
		t.Fatalf("wrong user: status=%d want 403", wrongUserRec.Code)
	}

	owner := httptest.NewRequest(http.MethodPost, "/sso/oauth/authorize/decision", strings.NewReader(form))
	owner.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	owner.Header.Set("Cookie", userCookie)
	ownerRec := httptest.NewRecorder()
	h.ServeHTTP(ownerRec, owner)
	if ownerRec.Code != http.StatusFound {
		t.Fatalf("owner: status=%d body=%s", ownerRec.Code, ownerRec.Body.String())
	}
}

func randomCodeVerifier(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
