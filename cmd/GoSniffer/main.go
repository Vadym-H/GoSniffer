package main

import (
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/Vadym-H/GoSniffer/internal/config"
	"github.com/Vadym-H/GoSniffer/internal/http-server/auth/session"
	"github.com/Vadym-H/GoSniffer/internal/http-server/handlers/auth/login"
	"github.com/Vadym-H/GoSniffer/internal/http-server/handlers/debug"
	"github.com/Vadym-H/GoSniffer/internal/http-server/handlers/metrics"
	confighandler "github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/config"
	"github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/device"
	fileopshandler "github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/fileops"
	metricsctlhandler "github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/metricsctl"
	packetshandler "github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/packets"
	recordinghandler "github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/recording"
	mwLogger "github.com/Vadym-H/GoSniffer/internal/http-server/middleware/logger"
	sessionMiddleware "github.com/Vadym-H/GoSniffer/internal/http-server/middleware/session"
	"github.com/Vadym-H/GoSniffer/internal/lib/logger/sl"
	setuplogger "github.com/Vadym-H/GoSniffer/internal/logger/setup"
	metricskg "github.com/Vadym-H/GoSniffer/internal/metrics"
	"github.com/Vadym-H/GoSniffer/internal/sniffer"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/capture"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/filemanager"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/toConsole"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/processor"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/processor/broadcaster"
	recordingservice "github.com/Vadym-H/GoSniffer/internal/sniffer/recording"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	cfg := config.MustLoad()
	log := setuplogger.SetupLogger(cfg.Env)

	log.Info("Starting GoSniffer...")

	// Initialize all handlers and services
	handlers := initializeHandlers(cfg, log)

	// Setup and start HTTP server
	router := setupRouter(handlers, log)
	startHTTPServer(router, cfg, log)

	// Initialize and start packet sniffer
	snifferState := initializeSnifferState()
	metricsCollector := metricskg.NewMetricsCollector()
	metrics.SetCollector(metricsCollector)

	// Create the sniffer restart callback
	startSnifferFn := createStartSnifferCallback(
		cfg,
		log,
		snifferState,
		metricsCollector,
		handlers.recordingService,
		handlers.metricsService,
		handlers.packetStreamHandler,
	)

	// Register callback and start sniffer
	handlers.filterHandler.SetRestartCallback(startSnifferFn)
	if err := startSnifferFn(cfg.Interface, &cfg.Filters); err != nil {
		log.Error("Failed to start initial sniffer", sl.Err(err))
	}

	// Keep application running
	select {}
}

// HandlerDependencies holds all HTTP handlers and services
type HandlerDependencies struct {
	authHandler           *login.AuthHandler
	deviceHandler         *device.DeviceHandler
	filterHandler         *confighandler.FilterHandler
	recordingHandler      *recordinghandler.RecordingHandler
	metricsControlHandler *metricsctlhandler.MetricsControlHandler
	fileOpsHandler        *fileopshandler.FileOpsHandler
	metricsHandler        *metrics.MetricsHandler
	recordingService      *recordingservice.RecordingService
	metricsService        *sniffer.MetricsService
	packetStreamHandler   *packetshandler.PacketStreamHandler
	store                 *session.StoreSession
}

// SnifferState tracks the current sniffer instance state
type SnifferState struct {
	currentPacketStream *capture.PacketStream
	currentStopChan     chan bool
	mu                  sync.Mutex
}

// initializeHandlers creates and configures all HTTP handlers and services
func initializeHandlers(cfg *config.Config, log *slog.Logger) *HandlerDependencies {
	// Initialize file manager
	fm, err := filemanager.NewFileManager(log)
	if err != nil {
		log.Error("Failed to initialize file manager", sl.Err(err))
		return nil
	}

	// Initialize session store and base services
	store := session.NewSessionStore()
	snifferService := sniffer.New(log)

	// Initialize auth and device handlers
	authHandler := login.NewAuthHandler(cfg, store)
	deviceHandler := device.NewDeviceHandler(log, snifferService)
	filterHandler := confighandler.NewFilterHandler(cfg, log)

	// Initialize recording service and handler
	recordingService := recordingservice.NewRecordingService(cfg, log, fm)
	recordingHandler := recordinghandler.NewRecordingHandler(log, recordingService)

	// Initialize metrics service and control handler
	metricsService := sniffer.NewMetricsService(log)
	metricsControlHandler := metricsctlhandler.NewMetricsControlHandler(log, metricsService)

	// Initialize file operations handler
	fileOpsHandler := fileopshandler.NewFileOpsHandler(log, fm.GetAbsBaseDir())

	// Initialize packet stream handler
	packetStreamHandler := packetshandler.NewPacketStreamHandler(log, nil, recordingService, fm.GetAbsBaseDir(), "")

	// Initialize metrics handler
	metricsHandler := metrics.NewMetricsHandler()

	// Return all dependencies
	return &HandlerDependencies{
		authHandler:           authHandler,
		deviceHandler:         deviceHandler,
		filterHandler:         filterHandler,
		recordingHandler:      recordingHandler,
		metricsControlHandler: metricsControlHandler,
		fileOpsHandler:        fileOpsHandler,
		metricsHandler:        metricsHandler,
		recordingService:      recordingService,
		metricsService:        metricsService,
		packetStreamHandler:   packetStreamHandler,
		store:                 store,
	}
}

// setupRouter creates and configures the HTTP router with all routes
func setupRouter(deps *HandlerDependencies, log *slog.Logger) *chi.Mux {
	router := chi.NewRouter()

	// Middleware
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

	// Protected sniffer routes
	router.Route("/sniffer", func(r chi.Router) {
		r.Use(sessionMiddleware.AuthMiddleware(deps.store))
		// Device endpoints
		r.Get("/ping", debug.Ping)
		r.Get("/devices", deps.deviceHandler.ListDevices)
		r.Post("/devices/select", deps.deviceHandler.ChooseDevice)

		// Filter and configuration endpoints
		r.Get("/filters", deps.filterHandler.GetFilters)
		r.Post("/filters/set", deps.filterHandler.SetFilters)
		r.Post("/configuration/apply", deps.filterHandler.ApplyConfiguration)

		// Recording endpoints
		r.Post("/recording/{format}/start", deps.recordingHandler.Start)
		r.Post("/recording/{format}/stop", deps.recordingHandler.Stop)
		r.Get("/recording/{format}/status", deps.recordingHandler.Status)

		// Metrics control endpoints
		r.Post("/metrics/start", deps.metricsControlHandler.Start)
		r.Post("/metrics/stop", deps.metricsControlHandler.Stop)
		r.Get("/metrics/status", deps.metricsControlHandler.Status)

		// File operations endpoints
		r.Get("/captures", deps.fileOpsHandler.ListCaptures)
		r.Get("/captures/download/*", deps.fileOpsHandler.DownloadCapture)
		r.Get("/packets/stream", deps.packetStreamHandler.StreamMetrics)
	})

	return router
}

// startHTTPServer starts the HTTP server in a goroutine
func startHTTPServer(router *chi.Mux, cfg *config.Config, log *slog.Logger) {
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
}

// initializeSnifferState creates the sniffer state tracker
func initializeSnifferState() *SnifferState {
	return &SnifferState{}
}

// createStartSnifferCallback creates the function that starts/restarts the sniffer
func createStartSnifferCallback(
	cfg *config.Config,
	log *slog.Logger,
	state *SnifferState,
	metricsCollector *metricskg.MetricsCollector,
	recordingService *recordingservice.RecordingService,
	metricsService *sniffer.MetricsService,
	packetStreamHandler *packetshandler.PacketStreamHandler,
) func(string, *config.BpfFilters) error {
	return func(device string, filters *config.BpfFilters) error {
		state.mu.Lock()
		defer state.mu.Unlock()

		log.Info("Starting sniffer with new configuration",
			slog.String("device", device),
			slog.Any("filters", filters))

		// Stop existing sniffer if running
		if state.currentPacketStream != nil && state.currentStopChan != nil {
			log.Info("Stopping existing sniffer before restart")
			if err := metricsService.Stop(); err != nil {
				log.Warn("Failed to stop metrics", sl.Err(err))
			}
			state.currentStopChan <- true
			time.Sleep(500 * time.Millisecond)
		}

		// Start new sniffer
		stream, err := capture.StartSniffing(device, filters, log)
		if err != nil {
			log.Error("Failed to start sniffing", slog.String("error", err.Error()))
			return err
		}

		state.currentPacketStream = stream
		state.currentStopChan = stream.Stop

		// Initialize broadcaster and connect services
		bcast := broadcaster.NewPacketBroadcaster(stream, log)
		bcast.Start()

		// Start console writer
		if cfg.EnableConsoleWriter {
			consoleWriter := toConsole.NewConsoleWriter(true) // true for compact format
			consoleProcessor := processor.NewPacketProcessor(1, consoleWriter, log)
			consoleChannel := bcast.RegisterConsumer(1000)
			consoleProcessor.Start(consoleChannel, stream)
		}
		recordingService.SetBroadcasterRef(bcast, device)
		metricsService.SetBroadcasterRef(bcast, device, metricsCollector)
		packetStreamHandler.SetBroadcaster(bcast)
		packetStreamHandler.SetInterfaceName(device)

		// Start metrics if enabled
		if cfg.EnableMetrics {
			if err := metricsService.Start(); err != nil {
				log.Error("Failed to start metrics", sl.Err(err))
			} else {
				log.Info("Metrics collection started")
			}
		}

		log.Info("Sniffer started successfully",
			slog.String("interface", device),
			slog.Bool("metrics_enabled", cfg.EnableMetrics))

		return nil
	}
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

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
