package main

import (
	"errors"
	"log/slog"
	"net/http"

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
	"github.com/Vadym-H/GoSniffer/internal/lib/logger/sl"
	setuplogger "github.com/Vadym-H/GoSniffer/internal/logger/setup"
	metricskg "github.com/Vadym-H/GoSniffer/internal/metrics"
	"github.com/Vadym-H/GoSniffer/internal/sniffer"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/capture"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/filemanager"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/processor/broadcaster"
	recordingservice "github.com/Vadym-H/GoSniffer/internal/sniffer/recording"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	cfg := config.MustLoad()
	log := setuplogger.SetupLogger(cfg.Env)

	log.Info("Starting GoSniffer...")

	// HTTP Server Setup

	store := session.NewSessionStore()
	snifferService := sniffer.New(log)
	authHandler := login.NewAuthHandler(cfg, store)
	deviceHandler := device.NewDeviceHandler(log, snifferService)
	filterHandler := confighandler.NewFilterHandler(cfg, log)

	// Initialize File Manager for recording and file ops
	fm, err := filemanager.NewFileManager(log)
	if err != nil {
		log.Error("Failed to initialize file manager", sl.Err(err))
		return
	}

	// Initialize Recording Service
	recordingService := recordingservice.NewRecordingService(cfg, log, fm)
	recordingHandler := recordinghandler.NewRecordingHandler(log, recordingService)

	// Initialize Metrics Service
	metricsService := sniffer.NewMetricsService(log)
	metricsControlHandler := metricsctlhandler.NewMetricsControlHandler(log, metricsService)

	// Initialize File Operations Handler
	fileOpsHandler := fileopshandler.NewFileOpsHandler(log, fm.GetAbsBaseDir())

	// Initialize packet stream handler with dependencies (broadcaster will be set later)
	packetStreamHandler := packetshandler.NewPacketStreamHandler(log, nil, recordingService, fm.GetAbsBaseDir(), "")

	router := chi.NewRouter()

	// Middleware Registration
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(mwLogger.New(log))
	router.Use(middleware.Recoverer)
	router.Use(middleware.URLFormat)

	// Public Routes
	router.Post("/login", authHandler.Login)
	router.Post("/logout", authHandler.Logout)

	// Metrics endpoint (public, no session required) - always available
	metricsHandler := metrics.NewMetricsHandler()
	router.Get("/metrics", metricsHandler.GetMetrics)

	// Protected Routes
	router.Route("/sniffer", func(r chi.Router) {
		//r.Use(sessionMiddleware.AuthMiddleware(store))

		r.Get("/ping", debug.Ping)
		r.Get("/devices", deviceHandler.ListDevices)
		r.Post("/devices/select", deviceHandler.ChooseDevice)

		r.Get("/filters", filterHandler.GetFilters)
		r.Post("/filters/set", filterHandler.SetFilters)

		// Recording endpoints - separate for each format
		r.Post("/recording/{format}/start", recordingHandler.Start)
		r.Post("/recording/{format}/stop", recordingHandler.Stop)
		r.Get("/recording/{format}/status", recordingHandler.Status)

		// Metrics control endpoints
		r.Post("/metrics/start", metricsControlHandler.Start)
		r.Post("/metrics/stop", metricsControlHandler.Stop)
		r.Get("/metrics/status", metricsControlHandler.Status)

		// File operations endpoints
		r.Get("/captures", fileOpsHandler.ListCaptures)
		r.Get("/captures/download/*", fileOpsHandler.DownloadCapture)
		// Packet stream endpoint
		r.Get("/packets/stream", packetStreamHandler.StreamMetrics)
	})

	srv := &http.Server{
		Addr:              cfg.Address,
		Handler:           router,
		ReadHeaderTimeout: cfg.HTTPServer.Timeout,
		WriteTimeout:      cfg.HTTPServer.Timeout,
		IdleTimeout:       cfg.HTTPServer.IdleTimeout,
	}

	// Start HTTP server in goroutine so capture can run
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("Failed to start server", sl.Err(err))
		}
	}()

	log.Info("HTTP server started", slog.String("addr", cfg.Address))

	// Packet Capture Setup (always running, independent of recording)
	interfaceName := "wlo1" // TODO: Get the real interface name

	go func() {
		stream, err := capture.StartSniffing(interfaceName, &cfg.Filters, log)
		if err != nil {
			log.Error("Failed to start sniffing", slog.String("error", err.Error()))
			return
		}
		broadcaster := broadcaster.NewPacketBroadcaster(stream, log)
		broadcaster.Start()

		// Set broadcaster reference for services
		recordingService.SetBroadcasterRef(broadcaster, interfaceName)

		// ALWAYS initialize metrics collector and set broadcaster (regardless of enable_metrics)
		// This allows API-based start/stop to work
		metricsCollector := metricskg.NewMetricsCollector()
		metricsService.SetBroadcasterRef(broadcaster, interfaceName, metricsCollector)
		metrics.SetCollector(metricsCollector)

		// Only auto-start metrics if enabled in config
		if cfg.EnableMetrics {
			if err := metricsService.Start(); err != nil {
				log.Error("Failed to start metrics on startup", sl.Err(err))
			} else {
				log.Info("Metrics collection auto-started (enable_metrics: true)")
			}
		}

		// Set packet stream handler
		packetStreamHandler.SetBroadcaster(broadcaster)
		packetStreamHandler.SetInterfaceName(interfaceName)

		log.Info("Packet capture initialized and broadcaster started",
			slog.String("interface", interfaceName),
			slog.Bool("metrics_auto_start", cfg.EnableMetrics))

		// Keep broadcaster running indefinitely
		// It will feed packets to recording service and metrics service as needed
	}()

	select {}
}

// TODO: Implement saving packets to files (PCAP, JSON, CSV)
// TODO: Implement Prometheus exporter(export monitoring metrics)
// TODO: Implement Web server UI
