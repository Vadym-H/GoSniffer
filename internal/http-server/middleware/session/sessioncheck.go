package sessionMiddleware

import (
	"net/http"

	"github.com/Vadym-H/GoSniffer/internal/http-server/auth/session"
)

func AuthMiddleware(store *session.StoreSession) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("session_token")
			if err != nil || !store.Valid(cookie.Value) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
