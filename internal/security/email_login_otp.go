package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// EmailLoginOTPStore holds hashed email-login OTPs keyed by JWT jti (in-memory, single-use).
type EmailLoginOTPStore struct {
	mu    sync.Mutex
	byJTI map[string]emailLoginOTP
}

type emailLoginOTP struct {
	Email     string
	CodeHash  string
	ExpiresAt int64
}

func NewEmailLoginOTPStore() *EmailLoginOTPStore {
	return &EmailLoginOTPStore{byJTI: map[string]emailLoginOTP{}}
}

func hashOTPCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// GenerateOTP6 returns a cryptographically random 6-digit code.
func GenerateOTP6() (string, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint32(buf[:]) % 1000000
	return fmt.Sprintf("%06d", n), nil
}

// NewTokenID returns a random token id suitable for JWT jti values.
func NewTokenID() string {
	return newID()
}

// Put stores a hashed OTP for jti until expiresAt (unix seconds).
func (s *EmailLoginOTPStore) Put(jti, email, code string, ttlSeconds int64) {
	if s == nil || jti == "" || email == "" || code == "" {
		return
	}
	if ttlSeconds <= 0 {
		ttlSeconds = EmailLoginOTPTTLSeconds
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(time.Now().Unix())
	s.byJTI[jti] = emailLoginOTP{
		Email:     email,
		CodeHash:  hashOTPCode(code),
		ExpiresAt: time.Now().Unix() + ttlSeconds,
	}
}

// Consume validates code for jti and removes the entry (single-use). Returns the email on success.
func (s *EmailLoginOTPStore) Consume(jti, code string) (string, bool) {
	if s == nil {
		return "", false
	}
	jti = strings.TrimSpace(jti)
	code = strings.TrimSpace(code)
	if jti == "" || len(code) != 6 {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	s.purgeExpiredLocked(now)
	entry, ok := s.byJTI[jti]
	if !ok || now >= entry.ExpiresAt {
		delete(s.byJTI, jti)
		return "", false
	}
	if entry.CodeHash != hashOTPCode(code) {
		return "", false
	}
	delete(s.byJTI, jti)
	return entry.Email, true
}

func (s *EmailLoginOTPStore) purgeExpiredLocked(now int64) {
	for k, v := range s.byJTI {
		if now >= v.ExpiresAt {
			delete(s.byJTI, k)
		}
	}
}
