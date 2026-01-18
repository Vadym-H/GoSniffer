package main

import (
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
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/toConsole"
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

	//HTTP server
	store := session.NewSessionStore()
	snifferService := sniffer.New(log)
	authHandler := login.NewAuthHandler(cfg, store)
	deviceHandler := device.NewDeviceHandler(log, snifferService)
	filterHandler := confighandler.NewFilterHandler(cfg, log)

	router := chi.NewRouter()

	//Middleware

	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(mwLogger.New(log))
	router.Use(middleware.Recoverer)
	router.Use(middleware.URLFormat)

	router.Post("/login", authHandler.Login)
	router.Post("/logout", authHandler.Logout)

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
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Failed to start server", sl.Err(err))
		}
	}()

	log.Info("HTTP server started", slog.String("addr", cfg.Address))

	// Start packet capture
	go func() {
		stream, err := capture.StartSniffing("wlo1", &cfg.Filters, log)
		if err != nil {
			log.Error("Failed to start sniffing", slog.String("error", err.Error()))
			return
		}
		broadcaster := broadcaster.NewPacketBroadcaster(stream, log)

		consoleWriter := toConsole.NewConsoleWriter(true)

		pcapWriter, err := pcapwriter.NewPcapWriter("capture.pcap", 30*time.Second, log)
		if err != nil {
			log.Error("Failed to create PCAP writer", slog.String("error", err.Error()))
			return
		}

		consoleProcessor := processor.NewPacketProcessor(cfg.ProcessorWorkers, consoleWriter, log)

		pcapProcessor := processor.NewPacketProcessor(cfg.ProcessorWorkers, pcapWriter, log)

		consoleChan := broadcaster.RegisterConsumer(10000)
		pcapChan := broadcaster.RegisterConsumer(10000)

		broadcaster.Start()
		consoleProcessor.Start(consoleChan, stream)
		pcapProcessor.Start(pcapChan, stream)

		time.Sleep(15 * time.Second)

		pcapProcessor.Stop()
		broadcaster.Stop()
		consoleWriter.Stop()

	}()

	select {}

	log.Info("GoSniffer stopped successfully")
}

//TODO: Implement saving packets to files (PCAP, JSON, CSV), and storing them on S3 server
//TODO: Implement Prometheus exporter(export monitoring metrics)
//TODO: Implement Web server UI
