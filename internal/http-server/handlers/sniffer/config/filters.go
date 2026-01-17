package confighandler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"

	"github.com/Vadym-H/GoSniffer/internal/config"
	"github.com/Vadym-H/GoSniffer/internal/lib/logger/sl"
)

type FilterHandler struct {
	Cfg *config.Config
	Mu  *sync.RWMutex
	log *slog.Logger
}

func NewFilterHandler(cfg *config.Config, log *slog.Logger) *FilterHandler {
	return &FilterHandler{
		Cfg: cfg,
		Mu:  &sync.RWMutex{},
		log: log,
	}
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
