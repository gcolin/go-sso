package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/model"
)

// UserDirectory indexes users from AppConfig.
type UserDirectory struct {
	mu      sync.RWMutex
	cfg     *config.AppConfig
	byID    map[string]*model.User
	byEmail map[string]*model.User
}

func NewUserDirectory(cfg *config.AppConfig) *UserDirectory {
	d := &UserDirectory{cfg: cfg}
	d.Reload()
	return d
}

func (d *UserDirectory) Reload() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.byID = map[string]*model.User{}
	d.byEmail = map[string]*model.User{}
	for i := range d.cfg.Users {
		u := &d.cfg.Users[i]
		d.byID[u.ID] = u
		d.byEmail[strings.ToLower(u.Email)] = u
	}
}

func (d *UserDirectory) FindByID(id string) (*model.User, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	u, ok := d.byID[id]
	return u, ok
}

func (d *UserDirectory) FindByEmail(email string) (*model.User, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	u, ok := d.byEmail[strings.ToLower(strings.TrimSpace(email))]
	return u, ok
}

func (d *UserDirectory) List() []model.User {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]model.User, 0, len(d.cfg.Users))
	out = append(out, d.cfg.Users...)
	return out
}

// Authenticate verifies local password credentials.
// Returns ("", status) where status is "" on success, "invalid_credentials", or "email_not_verified".
func (d *UserDirectory) Authenticate(email, password string) (*model.User, string) {
	u, ok := d.FindByEmail(email)
	if !ok || !u.HasLocalPassword() {
		return nil, "invalid_credentials"
	}
	if !VerifyPassword(password, u.PasswordHash) {
		return nil, "invalid_credentials"
	}
	if !u.IsEmailVerified() {
		return nil, "email_not_verified"
	}
	return u, ""
}

type AuthStatus int

const (
	AuthOK AuthStatus = iota
	AuthInvalidCredentials
	AuthEmailNotVerified
)

type PasswordVerifier struct {
	dir *UserDirectory
}

func NewPasswordVerifier(dir *UserDirectory) *PasswordVerifier {
	return &PasswordVerifier{dir: dir}
}

func (v *PasswordVerifier) AuthenticateStatus(email, password string) AuthStatus {
	_, status := v.dir.Authenticate(email, password)
	switch status {
	case "":
		return AuthOK
	case "email_not_verified":
		return AuthEmailNotVerified
	default:
		return AuthInvalidCredentials
	}
}

func (v *PasswordVerifier) Authenticate(email, password string) *model.User {
	u, status := v.dir.Authenticate(email, password)
	if status != "" {
		return nil
	}
	return u
}

type TotpSetupStore struct {
	mu   sync.Mutex
	byID map[string]string
}

func NewTotpSetupStore() *TotpSetupStore {
	return &TotpSetupStore{byID: map[string]string{}}
}

func (s *TotpSetupStore) Put(userID, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[userID] = secret
}

func (s *TotpSetupStore) Consume(userID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.byID[userID]
	if ok {
		delete(s.byID, userID)
	}
	return v, ok
}

func (s *TotpSetupStore) Remove(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, userID)
}

func (s *TotpSetupStore) Peek(userID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.byID[userID]
	return v, ok
}

func GenerateTotpSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

func VerifyTotpCode(secret, code string) bool {
	secret = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return false
	}
	step := time.Now().Unix() / 30
	for _, delta := range []int64{-1, 0, 1} {
		if hotp(key, uint64(step+delta)) == code {
			return true
		}
	}
	return false
}

// CurrentTotpCode returns the TOTP code for the current 30s window (tests / fixtures).
func CurrentTotpCode(secret string) string {
	secret = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return ""
	}
	return hotp(key, uint64(time.Now().Unix()/30))
}

func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", truncated%1000000)
}

type UserRegistry struct {
	cfg       *config.AppConfig
	loader    *config.Loader
	dir       *UserDirectory
	totpSetup *TotpSetupStore
	mu        sync.Mutex
}

func NewUserRegistry(cfg *config.AppConfig, loader *config.Loader, dir *UserDirectory, totpSetup *TotpSetupStore) *UserRegistry {
	return &UserRegistry{cfg: cfg, loader: loader, dir: dir, totpSetup: totpSetup}
}

func (r *UserRegistry) FindByID(id string) (*model.User, bool) { return r.dir.FindByID(id) }

func (r *UserRegistry) FindByEmail(email string) (*model.User, bool) {
	return r.dir.FindByEmail(email)
}

func (r *UserRegistry) MarkEmailVerified(userID string) error {
	if strings.TrimSpace(userID) == "" {
		return &UserValidationError{Msg: "user id is required"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.indexOf(userID)
	if idx < 0 {
		return &NotFoundError{Message: "user not found: " + userID}
	}
	verified := true
	r.cfg.Users[idx].EmailVerified = &verified
	if err := r.loader.Save(r.cfg); err != nil {
		return err
	}
	r.dir.Reload()
	return nil
}
func (r *UserRegistry) List() []model.User                      { return r.dir.List() }
func (r *UserRegistry) ListAll() []model.User { return r.dir.List() }

// CreateUser is the HTTP admin create shape: (email, name, type, password, maxStorageBytes).
func (r *UserRegistry) Create(email, name, typ, password string, maxStorageBytes int64) (*model.User, error) {
	var maxPtr *int64
	if maxStorageBytes > 0 {
		maxPtr = &maxStorageBytes
	}
	return r.createInternal(email, password, name, typ, maxPtr)
}

func (r *UserRegistry) createInternal(email, password, name, typ string, maxStorageBytes *int64) (*model.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	email = strings.TrimSpace(email)
	if email == "" || !strings.Contains(email, "@") {
		return nil, &UserValidationError{Msg: "email is invalid"}
	}
	if len(password) < 8 {
		return nil, &UserValidationError{Msg: "password must be at least 8 characters"}
	}
	if typ == "" {
		typ = model.TypeUser
	}
	if typ != model.TypeUser && typ != model.TypeAdmin {
		return nil, &UserValidationError{Msg: "type must be 'user' or 'admin'"}
	}
	if _, exists := r.dir.FindByEmail(email); exists {
		return nil, &ConflictError{Message: "email already in use: " + email}
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	u := model.User{
		ID:           newUserID(),
		Email:        email,
		PasswordHash: hash,
		Name:         strings.TrimSpace(name),
		Type:         typ,
	}
	if r.cfg.Mail.Enabled {
		verified := false
		u.EmailVerified = &verified
	}
	if maxStorageBytes != nil {
		u.MaxStorageBytes = *maxStorageBytes
	}
	r.cfg.Users = append(r.cfg.Users, u)
	if err := r.loader.Save(r.cfg); err != nil {
		r.cfg.Users = r.cfg.Users[:len(r.cfg.Users)-1]
		return nil, err
	}
	r.dir.Reload()
	created, _ := r.dir.FindByID(u.ID)
	return created, nil
}

func (r *UserRegistry) UpdateName(userID, name string) error {
	trimmed := strings.TrimSpace(name)
	if userID == "" {
		return &UserValidationError{Msg: "user id is required"}
	}
	if trimmed == "" {
		return &UserValidationError{Msg: "name is required"}
	}
	if len(trimmed) > 200 {
		return &UserValidationError{Msg: "name is too long"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.indexOf(userID)
	if idx < 0 {
		return &NotFoundError{Message: "user not found: " + userID}
	}
	r.cfg.Users[idx].Name = trimmed
	if err := r.loader.Save(r.cfg); err != nil {
		return err
	}
	r.dir.Reload()
	return nil
}

func (r *UserRegistry) UpdatePassword(userID, currentPassword, newPassword string) error {
	if userID == "" {
		return &UserValidationError{Msg: "user id is required"}
	}
	if strings.TrimSpace(currentPassword) == "" {
		return &UserValidationError{Msg: "current password is required"}
	}
	if len(newPassword) < 8 {
		return &UserValidationError{Msg: "password must be at least 8 characters"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.indexOf(userID)
	if idx < 0 {
		return &NotFoundError{Message: "user not found: " + userID}
	}
	u := &r.cfg.Users[idx]
	if !VerifyPassword(currentPassword, u.PasswordHash) {
		return &UserValidationError{Msg: "current password is invalid"}
	}
	if VerifyPassword(newPassword, u.PasswordHash) {
		return &UserValidationError{Msg: "new password must differ from current password"}
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	u.PasswordHash = hash
	if err := r.loader.Save(r.cfg); err != nil {
		return err
	}
	r.dir.Reload()
	return nil
}

// SetLocalPassword sets a password on an account that currently has none (session required by caller).
func (r *UserRegistry) SetLocalPassword(userID, newPassword string) error {
	if userID == "" {
		return &UserValidationError{Msg: "user id is required"}
	}
	if len(newPassword) < 8 {
		return &UserValidationError{Msg: "password must be at least 8 characters"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.indexOf(userID)
	if idx < 0 {
		return &NotFoundError{Message: "user not found: " + userID}
	}
	u := &r.cfg.Users[idx]
	if u.HasLocalPassword() {
		return &UserValidationError{Msg: "password is already set"}
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	u.PasswordHash = hash
	if err := r.loader.Save(r.cfg); err != nil {
		return err
	}
	r.dir.Reload()
	return nil
}

// RemoveLocalPassword clears the local password (and TOTP if enabled). Requires a linked IdP.
func (r *UserRegistry) RemoveLocalPassword(userID string) error {
	if userID == "" {
		return &UserValidationError{Msg: "user id is required"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.indexOf(userID)
	if idx < 0 {
		return &NotFoundError{Message: "user not found: " + userID}
	}
	u := &r.cfg.Users[idx]
	if !u.HasLocalPassword() {
		return &UserValidationError{Msg: "password is not set"}
	}
	if strings.TrimSpace(u.AuthProvider) == "" || strings.TrimSpace(u.ExternalSubject) == "" {
		return &UserValidationError{Msg: "cannot remove password without linked identity provider"}
	}
	if u.IsTotpEnabled() {
		u.TotpSecret = ""
		if r.totpSetup != nil {
			r.totpSetup.Remove(userID)
		}
	}
	u.PasswordHash = ""
	if err := r.loader.Save(r.cfg); err != nil {
		return err
	}
	r.dir.Reload()
	return nil
}

func (r *UserRegistry) BeginTotpSetup(userID string) (string, error) {
	if userID == "" {
		return "", &UserValidationError{Msg: "user id is required"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.indexOf(userID)
	if idx < 0 {
		return "", &NotFoundError{Message: "user not found: " + userID}
	}
	if r.cfg.Users[idx].IsTotpEnabled() {
		return "", &UserValidationError{Msg: "totp is already enabled"}
	}
	secret, err := GenerateTotpSecret()
	if err != nil {
		return "", err
	}
	if r.totpSetup == nil {
		return "", &UserValidationError{Msg: "totp setup unavailable"}
	}
	r.totpSetup.Put(userID, secret)
	return secret, nil
}

func (r *UserRegistry) ConfirmTotpSetup(userID, code string) error {
	if userID == "" {
		return &UserValidationError{Msg: "user id is required"}
	}
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return &UserValidationError{Msg: "totp code must be 6 digits"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.indexOf(userID)
	if idx < 0 {
		return &NotFoundError{Message: "user not found: " + userID}
	}
	if r.cfg.Users[idx].IsTotpEnabled() {
		return &UserValidationError{Msg: "totp is already enabled"}
	}
	if r.totpSetup == nil {
		return &UserValidationError{Msg: "totp setup unavailable"}
	}
	secret, ok := r.totpSetup.Consume(userID)
	if !ok {
		return &UserValidationError{Msg: "totp setup expired"}
	}
	if !VerifyTotpCode(secret, code) {
		r.totpSetup.Put(userID, secret)
		return &UserValidationError{Msg: "totp code is invalid"}
	}
	r.cfg.Users[idx].TotpSecret = secret
	if err := r.loader.Save(r.cfg); err != nil {
		return err
	}
	r.dir.Reload()
	return nil
}

func (r *UserRegistry) DisableTotpWithCredentials(userID, password, code string) error {
	if userID == "" {
		return &UserValidationError{Msg: "user id is required"}
	}
	u, ok := r.dir.FindByID(userID)
	if !ok {
		return &NotFoundError{Message: "user not found: " + userID}
	}
	if !u.IsTotpEnabled() {
		return &UserValidationError{Msg: "totp is not enabled"}
	}
	if u.HasLocalPassword() {
		if !VerifyPassword(password, u.PasswordHash) {
			return &UserValidationError{Msg: "password is invalid"}
		}
	}
	if !VerifyTotpCode(u.TotpSecret, code) {
		return &UserValidationError{Msg: "totp code is invalid"}
	}
	return r.DisableTotp(userID)
}

func BuildOtpAuthURI(email, secret, issuer string) string {
	if issuer == "" {
		issuer = "Datanode SSO"
	}
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	label := url.PathEscape(issuer + ":" + email)
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func (r *UserRegistry) Update(userID, email, name, typ, password string, emailVerified *bool, maxStorageBytes *int64) (*model.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.indexOf(userID)
	if idx < 0 {
		return nil, &NotFoundError{Message: "user not found: " + userID}
	}
	u := &r.cfg.Users[idx]
	if email != "" {
		trimmed := strings.TrimSpace(email)
		if !strings.Contains(trimmed, "@") {
			return nil, &UserValidationError{Msg: "email is invalid"}
		}
		if other, exists := r.dir.FindByEmail(trimmed); exists && other.ID != userID {
			return nil, &ConflictError{Message: "email already in use: " + trimmed}
		}
		u.Email = trimmed
	}
	if typ != "" {
		if typ != model.TypeUser && typ != model.TypeAdmin {
			return nil, &UserValidationError{Msg: "type must be 'user' or 'admin'"}
		}
		u.Type = typ
	}
	if name != "" {
		u.Name = strings.TrimSpace(name)
	}
	if password != "" {
		if len(password) < 8 {
			return nil, &UserValidationError{Msg: "password must be at least 8 characters"}
		}
		hash, err := HashPassword(password)
		if err != nil {
			return nil, err
		}
		u.PasswordHash = hash
	}
	if emailVerified != nil {
		u.EmailVerified = emailVerified
	}
	if maxStorageBytes != nil {
		u.MaxStorageBytes = *maxStorageBytes
	}
	if err := r.loader.Save(r.cfg); err != nil {
		return nil, err
	}
	r.dir.Reload()
	updated, _ := r.dir.FindByID(userID)
	return updated, nil
}

func (r *UserRegistry) Delete(userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.indexOf(userID)
	if idx < 0 {
		return &NotFoundError{Message: "user not found: " + userID}
	}
	r.cfg.Users = append(r.cfg.Users[:idx], r.cfg.Users[idx+1:]...)
	if err := r.loader.Save(r.cfg); err != nil {
		return err
	}
	r.dir.Reload()
	return nil
}

func (r *UserRegistry) DisableTotpByAdmin(userID string) error {
	return r.DisableTotp(userID)
}

func (r *UserRegistry) DisableTotp(userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.indexOf(userID)
	if idx < 0 {
		return &NotFoundError{Message: "user not found: " + userID}
	}
	if !r.cfg.Users[idx].IsTotpEnabled() {
		return &UserValidationError{Msg: "totp is not enabled"}
	}
	r.cfg.Users[idx].TotpSecret = ""
	if r.totpSetup != nil {
		r.totpSetup.Remove(userID)
	}
	if err := r.loader.Save(r.cfg); err != nil {
		return err
	}
	r.dir.Reload()
	return nil
}

func (r *UserRegistry) VerifyTotpLogin(userID, code string) (bool, error) {
	if userID == "" {
		return false, nil
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return false, &UserValidationError{Msg: "totp code is required"}
	}
	if len(code) != 6 {
		return false, &UserValidationError{Msg: "totp code must be 6 digits"}
	}
	u, ok := r.dir.FindByID(userID)
	if !ok || !u.IsTotpEnabled() {
		return false, nil
	}
	return VerifyTotpCode(u.TotpSecret, code), nil
}

// ResolveExternalLogin links or provisions a user after an external IdP login.
// linkingUserID is the session user performing an explicit link (empty = anonymous login).
func (r *UserRegistry) ResolveExternalLogin(providerID, externalSubject, email, name, linkingUserID string) (*model.User, error) {
	providerID = strings.TrimSpace(providerID)
	externalSubject = strings.TrimSpace(externalSubject)
	email = strings.TrimSpace(email)
	name = strings.TrimSpace(name)
	linkingUserID = strings.TrimSpace(linkingUserID)
	if providerID == "" {
		return nil, &UserValidationError{Msg: "auth provider is required"}
	}
	if externalSubject == "" {
		return nil, &UserValidationError{Msg: "external subject is required"}
	}
	if email == "" || !strings.Contains(email, "@") {
		return nil, &UserValidationError{Msg: "email is invalid"}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if u, ok := r.findByExternalLocked(providerID, externalSubject); ok {
		return u, nil
	}
	if idx := r.indexOfEmail(email); idx >= 0 {
		u := &r.cfg.Users[idx]
		hasIdP := strings.TrimSpace(u.AuthProvider) != "" || strings.TrimSpace(u.ExternalSubject) != ""
		// Never silently overwrite an existing IdP binding (prevents cross-IdP takeover).
		if hasIdP {
			if u.AuthProvider != providerID || u.ExternalSubject != externalSubject {
				linked := strings.TrimSpace(u.AuthProvider)
				if linked == "" {
					linked = "unknown"
				}
				return nil, &ExternalLoginNotAllowedError{
					Message:     "account already linked to another identity provider: " + linked,
					MessageKey:  "error.external.already_linked",
					MessageArgs: []string{linked},
				}
			}
		}
		// Verified password accounts require an explicit in-session link (same userID).
		if !hasIdP && u.IsEmailVerified() && u.HasLocalPassword() && linkingUserID != u.ID {
			return nil, &ExternalLoginNotAllowedError{
				Message:    "sign in with your password before linking an identity provider",
				MessageKey: "error.external.login_required_to_link",
			}
		}
		// Unverified local account: IdP email proves mailbox ownership.
		// Drop squatter credentials so they cannot keep password/2FA access.
		if !u.IsEmailVerified() {
			u.PasswordHash = ""
			u.TotpSecret = ""
			if r.totpSetup != nil {
				r.totpSetup.Remove(u.ID)
			}
		}
		u.AuthProvider = providerID
		u.ExternalSubject = externalSubject
		verified := true
		u.EmailVerified = &verified
		if name != "" && strings.TrimSpace(u.Name) == "" {
			u.Name = name
		}
		if err := r.loader.Save(r.cfg); err != nil {
			return nil, err
		}
		r.dir.Reload()
		updated, _ := r.dir.FindByID(u.ID)
		return updated, nil
	}

	if !r.cfg.Federation.AutoProvision {
		return nil, &ExternalLoginNotAllowedError{Message: "external user not allowed: " + email}
	}
	typ := strings.TrimSpace(r.cfg.Federation.DefaultUserType)
	if typ == "" {
		typ = model.TypeUser
	}
	if typ != model.TypeUser && typ != model.TypeAdmin {
		typ = model.TypeUser
	}
	display := name
	if display == "" {
		display = email
	}
	verified := true
	u := model.User{
		ID:              newUserID(),
		Email:           email,
		Name:            display,
		Type:            typ,
		AuthProvider:    providerID,
		ExternalSubject: externalSubject,
		EmailVerified:   &verified,
	}
	r.cfg.Users = append(r.cfg.Users, u)
	if err := r.loader.Save(r.cfg); err != nil {
		r.cfg.Users = r.cfg.Users[:len(r.cfg.Users)-1]
		return nil, err
	}
	r.dir.Reload()
	created, _ := r.dir.FindByID(u.ID)
	return created, nil
}

func (r *UserRegistry) findByExternalLocked(providerID, externalSubject string) (*model.User, bool) {
	for i := range r.cfg.Users {
		u := &r.cfg.Users[i]
		if u.AuthProvider == providerID && u.ExternalSubject == externalSubject {
			return u, true
		}
	}
	return nil, false
}

func (r *UserRegistry) indexOfEmail(email string) int {
	want := strings.ToLower(strings.TrimSpace(email))
	for i := range r.cfg.Users {
		if strings.ToLower(r.cfg.Users[i].Email) == want {
			return i
		}
	}
	return -1
}

func (r *UserRegistry) indexOf(userID string) int {
	for i := range r.cfg.Users {
		if r.cfg.Users[i].ID == userID {
			return i
		}
	}
	return -1
}

func newUserID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type UserValidationError struct{ Msg string }

func (e *UserValidationError) Error() string { return e.Msg }

type ConflictError struct{ Message string }

func (e *ConflictError) Error() string { return e.Message }

type NotFoundError struct{ Message string }

func (e *NotFoundError) Error() string { return e.Message }

type ExternalLoginNotAllowedError struct {
	Message     string
	MessageKey  string
	MessageArgs []string
}

func (e *ExternalLoginNotAllowedError) Error() string { return e.Message }

// UserConflictError / UserNotFoundError aliases.
type UserConflictError = ConflictError
type UserNotFoundError = NotFoundError
