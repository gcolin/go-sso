package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

const ExternalOAuthStateTTL = 10 * time.Minute

type ExternalOAuthPendingState struct {
	ProviderID   string
	CodeVerifier string
	ReturnURL    string
	ExpiresAt    time.Time
}

// ExternalOAuthStateStore holds PKCE/state for external IdP logins.
type ExternalOAuthStateStore struct {
	mu   sync.Mutex
	byID map[string]ExternalOAuthPendingState
}

func NewExternalOAuthStateStore() *ExternalOAuthStateStore {
	return &ExternalOAuthStateStore{byID: map[string]ExternalOAuthPendingState{}}
}

func (s *ExternalOAuthStateStore) Issue(providerID, codeVerifier, returnURL string, ttl time.Duration) string {
	if ttl <= 0 {
		ttl = ExternalOAuthStateTTL
	}
	state := randomURLToken(32)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	s.byID[state] = ExternalOAuthPendingState{
		ProviderID:   providerID,
		CodeVerifier: codeVerifier,
		ReturnURL:    returnURL,
		ExpiresAt:    time.Now().Add(ttl),
	}
	return state
}

func (s *ExternalOAuthStateStore) Consume(state string) (ExternalOAuthPendingState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	pending, ok := s.byID[state]
	if !ok {
		return ExternalOAuthPendingState{}, false
	}
	delete(s.byID, state)
	if time.Now().After(pending.ExpiresAt) {
		return ExternalOAuthPendingState{}, false
	}
	return pending, true
}

func (s *ExternalOAuthStateStore) purgeLocked() {
	now := time.Now()
	for k, v := range s.byID {
		if now.After(v.ExpiresAt) {
			delete(s.byID, k)
		}
	}
}

func randomURLToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
