package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Vadym-H/GoSniffer/internal/app"
	"github.com/Vadym-H/GoSniffer/internal/config"
	"github.com/Vadym-H/GoSniffer/internal/http-server/handlers/metrics"
	"github.com/Vadym-H/GoSniffer/internal/lib/logger/sl"
	setuplogger "github.com/Vadym-H/GoSniffer/internal/logger/setup"
	metricskg "github.com/Vadym-H/GoSniffer/internal/metrics"
)

func main() {
	cfg := config.MustLoad()
	log := setuplogger.SetupLogger(cfg.Env)

	log.Info("Starting GoSniffer...")

	handlers := app.InitializeHandlers(cfg, log)

	router := app.SetupRouter(handlers, log)
	srv := app.StartHTTPServer(router, cfg, log)

	snifferState := &app.SnifferState{}
	metricsCollector := metricskg.NewMetricsCollector()
	metrics.SetCollector(metricsCollector)

	startSnifferFn := app.CreateStartSnifferCallback(
		cfg,
		log,
		snifferState,
		metricsCollector,
		handlers.RecordingService,
		handlers.MetricsService,
		handlers.PacketStreamHandler,
	)

	handlers.FilterHandler.SetRestartCallback(startSnifferFn)
	if err := startSnifferFn(cfg.Interface, &cfg.Filters); err != nil {
		log.Error("Failed to start initial sniffer", sl.Err(err))
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down...")

	// Stop active recordings first so files are flushed and closed cleanly
	handlers.RecordingService.StopAll()
	snifferState.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("HTTP server shutdown error", sl.Err(err))
	}

	log.Info("Shutdown complete")
}
