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

func (s *StoreSession) Add(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = struct{}{}
}

func (s *StoreSession) Valid(token string) bool {
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
