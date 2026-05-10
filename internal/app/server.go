package app

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/Vadym-H/GoSniffer/internal/config"
	"github.com/Vadym-H/GoSniffer/internal/http-server/handlers/debug"
	mwLogger "github.com/Vadym-H/GoSniffer/internal/http-server/middleware/logger"
	sessionMiddleware "github.com/Vadym-H/GoSniffer/internal/http-server/middleware/session"
	"github.com/Vadym-H/GoSniffer/internal/lib/logger/sl"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func SetupRouter(deps *HandlerDependencies, log *slog.Logger) *chi.Mux {
	router := chi.NewRouter()

	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(mwLogger.New(log))
	router.Use(middleware.Recoverer)
	router.Use(middleware.URLFormat)
	router.Use(corsMiddleware)

	// Public routes
	router.Post("/login", deps.authHandler.Login)
	router.Post("/logout", deps.authHandler.Logout)
	router.Get("/metrics", deps.metricsHandler.GetMetrics)

	// Protected routes
	router.Route("/sniffer", func(r chi.Router) {
		r.Use(sessionMiddleware.AuthMiddleware(deps.store))

		r.Get("/ping", debug.Ping)

		r.Get("/devices", deps.deviceHandler.ListDevices)
		r.Post("/devices/select", deps.deviceHandler.ChooseDevice)

		r.Get("/filters", deps.FilterHandler.GetFilters)
		r.Post("/filters/set", deps.FilterHandler.SetFilters)
		r.Post("/configuration/apply", deps.FilterHandler.ApplyConfiguration)

		r.Post("/recording/{format}/start", deps.recordingHandler.Start)
		r.Post("/recording/{format}/stop", deps.recordingHandler.Stop)
		r.Get("/recording/{format}/status", deps.recordingHandler.Status)

		r.Post("/metrics/start", deps.metricsControlHandler.Start)
		r.Post("/metrics/stop", deps.metricsControlHandler.Stop)
		r.Get("/metrics/status", deps.metricsControlHandler.Status)

		r.Get("/captures", deps.fileOpsHandler.ListCaptures)
		r.Get("/captures/download/*", deps.fileOpsHandler.DownloadCapture)
		r.Get("/packets/stream", deps.PacketStreamHandler.StreamMetrics)
	})

	return router
}

// StartHTTPServer starts the HTTP server in a goroutine and returns it for graceful shutdown.
func StartHTTPServer(router *chi.Mux, cfg *config.Config, log *slog.Logger) *http.Server {
	srv := &http.Server{
		Addr:              cfg.Address,
		Handler:           router,
		ReadHeaderTimeout: cfg.HTTPServer.Timeout,
		WriteTimeout:      cfg.HTTPServer.Timeout,
		IdleTimeout:       cfg.HTTPServer.IdleTimeout,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("Failed to start server", sl.Err(err))
		}
	}()

	log.Info("HTTP server started", slog.String("addr", cfg.Address))
	return srv
}

// corsMiddleware adds CORS headers to allow browser requests from frontend
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "3600")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
