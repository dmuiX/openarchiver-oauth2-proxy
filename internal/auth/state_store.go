package auth

import (
	"sync"
	"time"
)

// AuthSession captures temporary data required to finish the OAuth2 code flow.
type AuthSession struct {
	CodeVerifier string
	ReturnTo     string
	CreatedAt    time.Time
}

// stateStore is a simple in-memory store for OAuth2 state -> session data.
type stateStore struct {
	mu    sync.Mutex
	ttl   time.Duration
	items map[string]AuthSession
}

func newStateStore(ttl time.Duration) *stateStore {
	return &stateStore{
		ttl:   ttl,
		items: make(map[string]AuthSession),
	}
}

func (s *stateStore) save(state string, session AuthSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	s.items[state] = session
}

func (s *stateStore) pop(state string) (AuthSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	value, ok := s.items[state]
	if ok {
		delete(s.items, state)
	}
	return value, ok
}

func (s *stateStore) cleanupLocked() {
	if len(s.items) == 0 {
		return
	}
	cutoff := time.Now().Add(-s.ttl)
	for key, session := range s.items {
		if session.CreatedAt.Before(cutoff) {
			delete(s.items, key)
		}
	}
}
