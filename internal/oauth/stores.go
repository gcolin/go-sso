package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/gcolin/go-sso/internal/model"
)

func sha256HexASCII(value string) string {
	sum := sha256.Sum256([]byte(value)) // ASCII codes are single-byte UTF-8
	return hex.EncodeToString(sum[:])
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func newRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

type IssuedCode struct {
	RawCode string
	Code    model.AuthorizationCode
}

type AuthorizationCodeStore struct {
	mu     sync.Mutex
	byHash map[string]model.AuthorizationCode
}

func NewAuthorizationCodeStore() *AuthorizationCodeStore {
	return &AuthorizationCodeStore{byHash: map[string]model.AuthorizationCode{}}
}

func (s *AuthorizationCodeStore) Issue(clientID, userID, redirectURI, codeChallenge, codeMethod, scope, nonce string, ttlSeconds int64) IssuedCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw := randomToken()
	hash := sha256HexASCII(raw)
	code := model.AuthorizationCode{
		CodeHash:            hash,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeMethod,
		Scope:               scope,
		Nonce:               nonce,
		ExpiresAt:           time.Now().Unix() + ttlSeconds,
	}
	s.byHash[hash] = code
	return IssuedCode{RawCode: raw, Code: code}
}

func (s *AuthorizationCodeStore) Consume(rawCode string) (model.AuthorizationCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := sha256HexASCII(rawCode)
	code, ok := s.byHash[hash]
	if !ok || code.Consumed || time.Now().Unix() >= code.ExpiresAt {
		delete(s.byHash, hash)
		return model.AuthorizationCode{}, false
	}
	delete(s.byHash, hash)
	return code, true
}

func (s *AuthorizationCodeStore) PurgeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for k, v := range s.byHash {
		if v.Consumed || now >= v.ExpiresAt {
			delete(s.byHash, k)
		}
	}
}

type AuthorizationRequestStore struct {
	mu   sync.Mutex
	byID map[string]model.AuthorizationRequest
}

func NewAuthorizationRequestStore() *AuthorizationRequestStore {
	return &AuthorizationRequestStore{byID: map[string]model.AuthorizationRequest{}}
}

func (s *AuthorizationRequestStore) Create(userID, clientID, redirectURI, scope, state, nonce, responseType, codeChallenge, codeMethod string, ttlSeconds int64) model.AuthorizationRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	req := model.AuthorizationRequest{
		RequestID:           newRequestID(),
		UserID:              userID,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		Nonce:               nonce,
		ResponseType:        responseType,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeMethod,
		ExpiresAt:           time.Now().Unix() + ttlSeconds,
	}
	s.byID[req.RequestID] = req
	return req
}

func (s *AuthorizationRequestStore) Peek(requestID string) (model.AuthorizationRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.byID[requestID]
	if !ok || time.Now().Unix() >= req.ExpiresAt {
		return model.AuthorizationRequest{}, false
	}
	return req, true
}

func (s *AuthorizationRequestStore) Consume(requestID string) (model.AuthorizationRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.byID[requestID]
	if !ok || time.Now().Unix() >= req.ExpiresAt {
		delete(s.byID, requestID)
		return model.AuthorizationRequest{}, false
	}
	delete(s.byID, requestID)
	return req, true
}

func (s *AuthorizationRequestStore) PurgeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for k, v := range s.byID {
		if now >= v.ExpiresAt {
			delete(s.byID, k)
		}
	}
}

type ConsentStore struct {
	mu sync.Mutex
	m  map[string]struct{}
}

func NewConsentStore() *ConsentStore {
	return &ConsentStore{m: map[string]struct{}{}}
}

func consentKey(userID, clientID, scope string) string {
	return userID + "|" + clientID + "|" + scope
}

func (s *ConsentStore) HasConsent(userID, clientID, scope string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[consentKey(userID, clientID, scope)]
	return ok
}

func (s *ConsentStore) Remember(userID, clientID, scope string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[consentKey(userID, clientID, scope)] = struct{}{}
}
