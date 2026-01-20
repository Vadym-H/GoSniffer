package sniffer

import (
	"fmt"
	"log/slog"
	"sync"

	metricskg "github.com/Vadym-H/GoSniffer/internal/metrics"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/processor/broadcaster"
)

// MetricsService manages the lifecycle of metrics aggregation
type MetricsService struct {
	mu               sync.RWMutex
	isRunning        bool
	log              *slog.Logger
	broadcasterRef   *broadcaster.PacketBroadcaster
	interfaceNameRef string
	metricsCollector *metricskg.MetricsCollector
	aggregator       *MetricsAggregator
	cancelFunc       func()
	consumerID       int
}

// NewMetricsService creates a new metrics service
func NewMetricsService(log *slog.Logger) *MetricsService {
	return &MetricsService{
		log: log,
	}
}

// SetBroadcasterRef sets the broadcaster reference for the metrics service
func (ms *MetricsService) SetBroadcasterRef(b *broadcaster.PacketBroadcaster, interfaceName string, mc *metricskg.MetricsCollector) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.broadcasterRef = b
	ms.interfaceNameRef = interfaceName
	ms.metricsCollector = mc
}

// Start begins metrics collection
func (ms *MetricsService) Start() error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if ms.isRunning {
		return fmt.Errorf("metrics already running")
	}

	if ms.broadcasterRef == nil {
		return fmt.Errorf("broadcaster not initialized")
	}

	if ms.metricsCollector == nil {
		return fmt.Errorf("metrics collector not initialized")
	}

	ms.isRunning = true
	ms.aggregator = NewMetricsAggregator(ms.interfaceNameRef, ms.metricsCollector, ms.log)

	// Register consumer for metrics
	ch := ms.broadcasterRef.RegisterConsumer(10000)
	ms.consumerID = len(ms.broadcasterRef.GetConsumers()) - 1

	// Start the aggregator
	ms.aggregator.Start(ch, ms.broadcasterRef.GetStream())

	ms.log.Info("Metrics service started")
	return nil
}

// Stop ends metrics collection
func (ms *MetricsService) Stop() error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if !ms.isRunning {
		return fmt.Errorf("metrics not running")
	}

	if ms.aggregator != nil {
		ms.aggregator.Stop()
	}

	if ms.consumerID >= 0 {
		ms.broadcasterRef.UnregisterConsumer(ms.consumerID)
	}

	ms.isRunning = false
	ms.log.Info("Metrics service stopped")
	return nil
}

// IsRunning returns whether metrics collection is currently running
func (ms *MetricsService) IsRunning() bool {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	return ms.isRunning
}
