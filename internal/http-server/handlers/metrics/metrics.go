package metrics

import (
	"net/http"
	"sync"

	metricskg "github.com/Vadym-H/GoSniffer/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsHandler handles HTTP requests for metrics
type MetricsHandler struct {
	mu        sync.RWMutex
	collector *metricskg.MetricsCollector
}

var (
	globalHandler *MetricsHandler
	globalMu      sync.RWMutex
)

// NewMetricsHandler creates a new metrics handler
func NewMetricsHandler() *MetricsHandler {
	globalMu.Lock()
	defer globalMu.Unlock()

	if globalHandler == nil {
		globalHandler = &MetricsHandler{
			collector: nil,
		}
	}
	return globalHandler
}

// SetCollector sets the metrics collector (called from main after metrics initialization)
func SetCollector(collector *metricskg.MetricsCollector) {
	globalMu.Lock()
	defer globalMu.Unlock()

	if globalHandler == nil {
		globalHandler = &MetricsHandler{
			collector: collector,
		}
	} else {
		globalHandler.collector = collector
	}
}

// GetMetrics returns metrics in Prometheus text format
func (h *MetricsHandler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	// Use Prometheus HTTP handler to format response
	promhttp.Handler().ServeHTTP(w, r)
}
