package confighandler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"

	"github.com/Vadym-H/GoSniffer/internal/config"
	"github.com/Vadym-H/GoSniffer/internal/lib/logger/sl"
)

// ConfigurationRequest represents the request to apply new configuration
type ConfigurationRequest struct {
	DeviceName string            `json:"device_name"`
	Filters    config.BpfFilters `json:"filters"`
}

type FilterHandler struct {
	Cfg           *config.Config
	Mu            *sync.RWMutex
	log           *slog.Logger
	onRestartFunc func(string, *config.BpfFilters) error
}

func NewFilterHandler(cfg *config.Config, log *slog.Logger) *FilterHandler {
	return &FilterHandler{
		Cfg: cfg,
		Mu:  &sync.RWMutex{},
		log: log,
	}
}

// SetRestartCallback sets the function to call when configuration needs to be applied
func (h *FilterHandler) SetRestartCallback(fn func(string, *config.BpfFilters) error) {
	h.onRestartFunc = fn
}

func (h *FilterHandler) GetFilters(w http.ResponseWriter, r *http.Request) {
	h.Mu.RLock()
	defer h.Mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(h.Cfg.Filters)
	if err != nil {
		h.log.Warn("Failed to encode filters", sl.Err(err))
		http.Error(w, "Failed to encode filters: "+err.Error(), http.StatusInternalServerError)
	}
}

func (h *FilterHandler) SetFilters(w http.ResponseWriter, r *http.Request) {
	var newFilters config.BpfFilters
	if err := json.NewDecoder(r.Body).Decode(&newFilters); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	h.Mu.Lock()
	h.Cfg.Filters = newFilters
	h.Mu.Unlock()

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("Filters updated")); err != nil {
		h.log.Warn("Failed to write response", sl.Err(err))
	}
}

// ApplyConfiguration applies a new device and filter configuration, then restarts the sniffer
func (h *FilterHandler) ApplyConfiguration(w http.ResponseWriter, r *http.Request) {
	var req ConfigurationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.log.Warn("Invalid request body", sl.Err(err))
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.DeviceName == "" {
		http.Error(w, "Device name is required", http.StatusBadRequest)
		return
	}

	h.Mu.Lock()
	h.Cfg.Filters = req.Filters
	h.Mu.Unlock()

	h.log.Info("Applying new configuration",
		slog.String("device", req.DeviceName),
		slog.Any("filters", req.Filters))

	// Call the restart callback if set
	if h.onRestartFunc != nil {
		if err := h.onRestartFunc(req.DeviceName, &req.Filters); err != nil {
			h.log.Error("Failed to apply configuration", sl.Err(err))
			http.Error(w, "Failed to apply configuration: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"message": "Configuration applied and sniffer restarted",
	}); err != nil {
		h.log.Error("Failed to encode response", sl.Err(err))
	}
}
