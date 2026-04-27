package session

import (
	"sync"
)

type StoreSession struct {
	mu     sync.Mutex
	tokens map[string]struct{}
}

func NewSessionStore() *StoreSession {
	return &StoreSession{
		tokens: make(map[string]struct{}),
	}
}

// Add adds a token to the session store
func (s *StoreSession) Add(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = struct{}{}
}

// IsValid checks if a token is valid
func (s *StoreSession) IsValid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.tokens[token]
	return ok
}

func (s *StoreSession) Remove(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
}
