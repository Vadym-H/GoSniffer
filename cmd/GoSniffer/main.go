package main

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/Vadym-H/GoSniffer/internal/config"
	"github.com/Vadym-H/GoSniffer/internal/http-server/auth/session"
	"github.com/Vadym-H/GoSniffer/internal/http-server/handlers/auth/login"
	"github.com/Vadym-H/GoSniffer/internal/http-server/handlers/debug"
	confighandler "github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/config"
	"github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/device"
	mwLogger "github.com/Vadym-H/GoSniffer/internal/http-server/middleware/logger"
	sessionMiddleware "github.com/Vadym-H/GoSniffer/internal/http-server/middleware/session"
	"github.com/Vadym-H/GoSniffer/internal/lib/logger/sl"
	setuplogger "github.com/Vadym-H/GoSniffer/internal/logger/setup"
	"github.com/Vadym-H/GoSniffer/internal/sniffer"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/capture"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/filemanager"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/toConsole"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/toFife/csvwriter"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/toFife/jsonwriter"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/toFife/pcapwriter"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/processor"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/processor/broadcaster"
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

	// Protected Routes
	router.Route("/sniffer", func(r chi.Router) {
		r.Use(sessionMiddleware.AuthMiddleware(store))

		r.Get("/ping", debug.Ping)
		r.Get("/devices", deviceHandler.ListDevices)
		r.Post("/devices/select", deviceHandler.ChooseDevice)

		r.Get("/filters", filterHandler.GetFilters)
		r.Post("/filters/set", filterHandler.SetFilters)
		//r.Post("/start", snifferHandler.Start)
		//r.Post("/stop", snifferHandler.Stop)
		//r.Get("/status", snifferHandler.Status)
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

	// Initialize File Manager
	fm, err := filemanager.NewFileManager(log)
	if err != nil {
		log.Error("Failed to initialize file manager", sl.Err(err))
		return
	}

	// Packet Capture and Writer Testing

	interfaceName := "wlo1" // TODO: Get the real interface name

	go func() {
		stream, err := capture.StartSniffing(interfaceName, &cfg.Filters, log)
		if err != nil {
			log.Error("Failed to start sniffing", slog.String("error", err.Error()))
			return
		}
		broadcaster := broadcaster.NewPacketBroadcaster(stream, log)

		// Console Writer Setup
		consoleWriter := toConsole.NewConsoleWriter(true)
		consoleProcessor := processor.NewPacketProcessor(cfg.ProcessorWorkers, consoleWriter, log)

		// PCAP Writer Setup
		pcapWriter, err := pcapwriter.NewPcapWriter(interfaceName, 30*time.Second, log, fm)
		if err != nil {
			log.Error("Failed to create PCAP writer", slog.String("error", err.Error()))
			return
		}
		pcapProcessor := processor.NewPacketProcessor(cfg.ProcessorWorkers, pcapWriter, log)

		// CSV Writer Setup
		csvWriter, err := csvwriter.NewCSVWriter(interfaceName, 30*time.Second, log, fm)
		if err != nil {
			log.Error("Failed to create CSV writer", slog.String("error", err.Error()))
			return
		}
		csvProcessor := processor.NewPacketProcessor(cfg.ProcessorWorkers, csvWriter, log)

		// JSON Writer Setup
		jsonWriter, err := jsonwriter.NewJSONWriter(interfaceName, 30*time.Second, log, fm)
		if err != nil {
			log.Error("Failed to create JSON writer", slog.String("error", err.Error()))
			return
		}
		jsonProcessor := processor.NewPacketProcessor(cfg.ProcessorWorkers, jsonWriter, log)

		// Register Consumers and Start Processing
		consoleChan := broadcaster.RegisterConsumer(10000)
		pcapChan := broadcaster.RegisterConsumer(10000)
		csvChan := broadcaster.RegisterConsumer(10000)
		jsonChan := broadcaster.RegisterConsumer(10000)

		broadcaster.Start()
		consoleProcessor.Start(consoleChan, stream)
		pcapProcessor.Start(pcapChan, stream)
		csvProcessor.Start(csvChan, stream)
		jsonProcessor.Start(jsonChan, stream)

		log.Info("All packet processors started",
			slog.String("console_writer", "active"),
			slog.String("pcap_writer", "active"),
			slog.String("csv_writer", "active"),
			slog.String("json_writer", "active"))

		// Run for 30 seconds
		time.Sleep(30 * time.Second)

		// Graceful Shutdown

		log.Info("Stopping packet processors...")

		jsonProcessor.Stop()
		csvProcessor.Stop()
		pcapProcessor.Stop()
		broadcaster.Stop()
		consoleWriter.Stop()

		// Stop the packet capture loop
		log.Info("Stopping packet capture...")
		stream.Stop <- true

		// Give goroutines time to finish
		time.Sleep(1 * time.Second)

		log.Info("All packet processors stopped successfully")

	}()

	select {}
}

// TODO: Implement saving packets to files (PCAP, JSON, CSV)
// TODO: Implement Prometheus exporter(export monitoring metrics)
// TODO: Implement Web server UI
