package login

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"github.com/Vadym-H/GoSniffer/internal/config"
	"github.com/Vadym-H/GoSniffer/internal/http-server/auth/session"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	cfg   *config.Config
	Store *session.StoreSession
}

func NewAuthHandler(cfg *config.Config, store *session.StoreSession) *AuthHandler {
	return &AuthHandler{cfg: cfg, Store: store}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		http.Error(w, "EMPTY PASSWORD", http.StatusBadRequest)
		return
	}

	// Check against bcrypt hash from config
	if bcrypt.CompareHashAndPassword(h.cfg.PasswordHash, []byte(req.Password)) != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token := uuid.New().String()
	h.Store.Add(token)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   3600,
	})

	w.WriteHeader(http.StatusOK)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		h.Store.Remove(cookie.Value)
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			MaxAge:   -1,
		})
	}
	w.WriteHeader(http.StatusOK)
}
