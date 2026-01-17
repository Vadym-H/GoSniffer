package main

import (
	"log/slog"
	"net/http"

	"github.com/Vadym-H/GoSniffer/internal/config"
	"github.com/Vadym-H/GoSniffer/internal/http-server/auth/session"
	"github.com/Vadym-H/GoSniffer/internal/http-server/handlers/auth/login"
	"github.com/Vadym-H/GoSniffer/internal/http-server/handlers/debug"
	confighandler "github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/config"
	"github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/device"
	mwLogger "github.com/Vadym-H/GoSniffer/internal/http-server/middleware/logger"
	sessionMiddleware "github.com/Vadym-H/GoSniffer/internal/http-server/middleware/session"
	"github.com/Vadym-H/GoSniffer/internal/lib/logger/sl"
	"github.com/Vadym-H/GoSniffer/internal/logger/setup"
	"github.com/Vadym-H/GoSniffer/internal/sniffer"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/capture"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/toConsole"
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
	if err := srv.ListenAndServe(); err != nil {
		log.Error("Failed to start server", sl.Err(err))
	}

	stream, err := capture.StartSniffing("eth0", filters, log)
	if err != nil {
		log.Error("Failed to start sniffing", slog.String("error", err.Error()))
		return
	}

	broadcaster := broadcaster.NewPacketBroadcaster(stream, log)

	consoleWriter := toConsole.NewConsoleWriter(true)

	consoleProcessor := processor.NewPacketProcessor(4, consoleWriter, log)

	consoleChan := broadcaster.RegisterConsumer(10000)
	
	broadcaster.Start()
	consoleProcessor.Start(consoleChan)

	//device, err := capture.ChoosingDevice(log, 0) //TODO: Implement real choosing the device
	//if err != nil {
	//	log.Error("Failed to find network devices", slog.String("error", err.Error()))
	//	return
	//}
	//
	//stream, err := capture.StartSniffing(device, &cfg.Filters, log)
	//if err != nil {
	//	log.Error("Failed to start sniffing", slog.String("error", err.Error()))
	//	return
	//}
	//
	//log.Info("Packet capture started. Press Ctrl+C to stop...")
	//
	//// Start packet processor with worker pool
	//numWorkers := cfg.ProcessorWorkers
	//if numWorkers == 0 {
	//	numWorkers = 4 // Default to 4 workers
	//}
	//writer := toConsole.NewConsoleWriter(false)
	//
	//proc := processor.NewPacketProcessor(numWorkers, writer, log)
	//proc.Start(stream)

	//sigChan := make(chan os.Signal, 1)
	//signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	//<-sigChan
	//
	//log.Info("Stopping capture...")
	//stream.Stop <- true
	//proc.Stop()

	log.Info("GoSniffer stopped successfully")
}

//TODO: Implement saving packets to files (PCAP, JSON, CSV), and storing them on S3 server
//TODO: Implement Prometheus exporter(export monitoring metrics)
//TODO: Implement Web server UI
