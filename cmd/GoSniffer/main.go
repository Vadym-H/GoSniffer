package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Vadym-H/GoSniffer/internal/config"
	"github.com/Vadym-H/GoSniffer/internal/logger/setup"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/capture"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/toConsole"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/processor"
)

func main() {
	cfg := config.MustLoad()
	log := setuplogger.SetupLogger(cfg.Env)

	log.Info("Starting GoSniffer...")

	device, err := capture.ChoosingDevice(log, 0) //TODO: Implement real choosing the device
	if err != nil {
		log.Error("Failed to find network devices", slog.String("error", err.Error()))
		return
	}

	stream, err := capture.StartSniffing(device, &cfg.Filters, log)
	if err != nil {
		log.Error("Failed to start sniffing", slog.String("error", err.Error()))
		return
	}

	// Start packet processor with worker pool
	numWorkers := cfg.ProcessorWorkers
	if numWorkers == 0 {
		numWorkers = 4 // Default to 4 workers
	}
	writer := toConsole.NewConsoleWriter(false)

	proc := processor.NewPacketProcessor(numWorkers, writer, log)
	proc.Start(stream)

	log.Info("Packet capture started. Press Ctrl+C to stop...")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Info("Stopping capture...")
	stream.Stop <- true
	proc.Stop()

	log.Info("GoSniffer stopped successfully")
}
