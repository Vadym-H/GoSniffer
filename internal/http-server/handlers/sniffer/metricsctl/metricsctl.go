package metricsctl

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Vadym-H/GoSniffer/internal/lib/logger/sl"
	"github.com/Vadym-H/GoSniffer/internal/sniffer"
)

// MetricsControlStatus represents the metrics control status
type MetricsControlStatus struct {
	IsRunning bool   `json:"is_running"`
	Status    string `json:"status"`
}

// MetricsControlHandler handles metrics start/stop endpoints
type MetricsControlHandler struct {
	log            *slog.Logger
	metricsService *sniffer.MetricsService
}

// NewMetricsControlHandler creates a new metrics control handler
func NewMetricsControlHandler(log *slog.Logger, metricsService *sniffer.MetricsService) *MetricsControlHandler {
	return &MetricsControlHandler{
		log:            log,
		metricsService: metricsService,
	}
}

// Start handles POST /sniffer/metrics/start
func (h *MetricsControlHandler) Start(w http.ResponseWriter, _ *http.Request) {
	if err := h.metricsService.Start(); err != nil {
		h.log.Warn("Failed to start metrics", sl.Err(err))
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{"message": "Metrics collection started"}); err != nil {
		h.log.Error("Failed to encode response", sl.Err(err))
	}
}

// Stop handles POST /sniffer/metrics/stop
func (h *MetricsControlHandler) Stop(w http.ResponseWriter, _ *http.Request) {
	if err := h.metricsService.Stop(); err != nil {
		h.log.Warn("Failed to stop metrics", sl.Err(err))
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{"message": "Metrics collection stopped"}); err != nil {
		h.log.Error("Failed to encode response", sl.Err(err))
	}
}

// Status handles GET /sniffer/metrics/status
func (h *MetricsControlHandler) Status(w http.ResponseWriter, _ *http.Request) {
	isRunning := h.metricsService.IsRunning()

	status := MetricsControlStatus{
		IsRunning: isRunning,
	}

	if isRunning {
		status.Status = "running"
	} else {
		status.Status = "stopped"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(status); err != nil {
		h.log.Error("Failed to encode status response", sl.Err(err))
	}
}
