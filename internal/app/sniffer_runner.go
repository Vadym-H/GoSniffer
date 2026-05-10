package app

import (
	"log/slog"
	"sync"

	"github.com/Vadym-H/GoSniffer/internal/config"
	packetshandler "github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/packets"
	"github.com/Vadym-H/GoSniffer/internal/lib/logger/sl"
	metricskg "github.com/Vadym-H/GoSniffer/internal/metrics"
	"github.com/Vadym-H/GoSniffer/internal/sniffer"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/capture"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/toConsole"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/processor"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/processor/broadcaster"
	recordingservice "github.com/Vadym-H/GoSniffer/internal/sniffer/recording"
)

// SnifferState tracks the current sniffer instance state
type SnifferState struct {
	currentPacketStream *capture.PacketStream
	currentStopChan     chan bool
	currentBroadcaster  *broadcaster.PacketBroadcaster
	mu                  sync.Mutex
}

func (s *SnifferState) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentBroadcaster != nil {
		s.currentBroadcaster.Stop()
	}
	if s.currentPacketStream != nil {
		s.currentStopChan <- true
		<-s.currentPacketStream.Done
	}
}

func CreateStartSnifferCallback(
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

		if state.currentPacketStream != nil {
			log.Info("Stopping existing sniffer before restart")
			if err := metricsService.Stop(); err != nil {
				log.Warn("Failed to stop metrics", sl.Err(err))
			}
			if state.currentBroadcaster != nil {
				state.currentBroadcaster.Stop()
				state.currentBroadcaster = nil
			}
			state.currentStopChan <- true
			<-state.currentPacketStream.Done
		}

		stream, err := capture.StartSniffing(device, filters, log)
		if err != nil {
			log.Error("Failed to start sniffing", slog.String("error", err.Error()))
			return err
		}

		state.currentPacketStream = stream
		state.currentStopChan = stream.Stop

		bcast := broadcaster.NewPacketBroadcaster(stream, log)
		bcast.Start()
		state.currentBroadcaster = bcast

		if cfg.EnableConsoleWriter {
			const compactFormat = true
			consoleWriter := toConsole.NewConsoleWriter(compactFormat)
			consoleProcessor := processor.NewPacketProcessor(1, consoleWriter, log)
			consoleChannel := bcast.RegisterConsumer(1000)
			consoleProcessor.Start(consoleChannel, stream)
		}

		recordingService.SetBroadcasterRef(bcast, device)
		metricsService.SetBroadcasterRef(bcast, device, metricsCollector)
		packetStreamHandler.SetBroadcaster(bcast)
		packetStreamHandler.SetInterfaceName(device)

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
