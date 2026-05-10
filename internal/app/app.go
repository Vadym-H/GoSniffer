package app

import (
	"log/slog"

	"github.com/Vadym-H/GoSniffer/internal/config"
	"github.com/Vadym-H/GoSniffer/internal/http-server/auth/session"
	"github.com/Vadym-H/GoSniffer/internal/http-server/handlers/auth/login"
	"github.com/Vadym-H/GoSniffer/internal/http-server/handlers/metrics"
	confighandler "github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/config"
	"github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/device"
	fileopshandler "github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/fileops"
	metricsctlhandler "github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/metricsctl"
	packetshandler "github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/packets"
	recordinghandler "github.com/Vadym-H/GoSniffer/internal/http-server/handlers/sniffer/recording"
	"github.com/Vadym-H/GoSniffer/internal/lib/logger/sl"
	"github.com/Vadym-H/GoSniffer/internal/sniffer"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/filemanager"
	recordingservice "github.com/Vadym-H/GoSniffer/internal/sniffer/recording"
)

// HandlerDependencies holds all HTTP handlers and services.
// Exported fields are those accessed directly from main.
type HandlerDependencies struct {
	FilterHandler       *confighandler.FilterHandler
	RecordingService    *recordingservice.RecordingService
	MetricsService      *sniffer.MetricsService
	PacketStreamHandler *packetshandler.PacketStreamHandler

	authHandler           *login.AuthHandler
	deviceHandler         *device.DeviceHandler
	recordingHandler      *recordinghandler.RecordingHandler
	metricsControlHandler *metricsctlhandler.MetricsControlHandler
	fileOpsHandler        *fileopshandler.FileOpsHandler
	metricsHandler        *metrics.MetricsHandler
	store                 *session.StoreSession
}

func InitializeHandlers(cfg *config.Config, log *slog.Logger) *HandlerDependencies {
	fm, err := filemanager.NewFileManager(log)
	if err != nil {
		log.Error("Failed to initialize file manager", sl.Err(err))
		return nil
	}

	store := session.NewSessionStore()
	snifferService := sniffer.New(log)

	authHandler := login.NewAuthHandler(cfg, store)
	deviceHandler := device.NewDeviceHandler(log, snifferService)
	filterHandler := confighandler.NewFilterHandler(cfg, log)

	recordingService := recordingservice.NewRecordingService(cfg, log, fm)
	recordingHandler := recordinghandler.NewRecordingHandler(log, recordingService)

	metricsService := sniffer.NewMetricsService(log)
	metricsControlHandler := metricsctlhandler.NewMetricsControlHandler(log, metricsService)

	fileOpsHandler := fileopshandler.NewFileOpsHandler(log, fm.GetAbsBaseDir())
	packetStreamHandler := packetshandler.NewPacketStreamHandler(log, nil, recordingService, fm.GetAbsBaseDir(), "")
	metricsHandler := metrics.NewMetricsHandler()

	return &HandlerDependencies{
		FilterHandler:         filterHandler,
		RecordingService:      recordingService,
		MetricsService:        metricsService,
		PacketStreamHandler:   packetStreamHandler,
		authHandler:           authHandler,
		deviceHandler:         deviceHandler,
		recordingHandler:      recordingHandler,
		metricsControlHandler: metricsControlHandler,
		fileOpsHandler:        fileOpsHandler,
		metricsHandler:        metricsHandler,
		store:                 store,
	}
}
