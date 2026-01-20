package recording

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Vadym-H/GoSniffer/internal/lib/logger/sl"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/recording"
	"github.com/go-chi/chi/v5"
)

// RecordingHandler handles recording control endpoints
type RecordingHandler struct {
	log              *slog.Logger
	recordingService *recording.RecordingService
}

// NewRecordingHandler creates a new recording handler
func NewRecordingHandler(log *slog.Logger, recordingService *recording.RecordingService) *RecordingHandler {
	return &RecordingHandler{
		log:              log,
		recordingService: recordingService,
	}
}

// StartRequest represents the request body for starting a recording
type StartRequest struct {
	DurationSeconds int `json:"duration_seconds"`
}

// Start handles POST /sniffer/recording/{format}/start
func (h *RecordingHandler) Start(w http.ResponseWriter, r *http.Request) {
	format := recording.RecordingFormat(chi.URLParam(r, "format"))

	var req StartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.log.Warn("Invalid request body", sl.Err(err))
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.recordingService.StartRecording(format, req.DurationSeconds); err != nil {
		h.log.Warn(
			"Failed to start recording",
			slog.String("format", string(format)),
			sl.Err(err),
		)
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(
		map[string]string{"message": "Recording started"},
	); err != nil {
		h.log.Error("Failed to encode response", sl.Err(err))
	}
}

// Stop handles POST /sniffer/recording/{format}/stop
func (h *RecordingHandler) Stop(w http.ResponseWriter, r *http.Request) {
	format := recording.RecordingFormat(chi.URLParam(r, "format"))

	if err := h.recordingService.StopRecording(format); err != nil {
		h.log.Warn(
			"Failed to stop recording",
			slog.String("format", string(format)),
			sl.Err(err),
		)
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(
		map[string]string{"message": "Recording stopped"},
	); err != nil {
		h.log.Error("Failed to encode response", sl.Err(err))
	}
}

// Status handles GET /sniffer/recording/{format}/status
func (h *RecordingHandler) Status(w http.ResponseWriter, r *http.Request) {
	format := recording.RecordingFormat(chi.URLParam(r, "format"))

	status := h.recordingService.GetStatus(format)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}
