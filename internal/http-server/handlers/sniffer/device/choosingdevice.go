package device

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Vadym-H/GoSniffer/internal/sniffer"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/capture"
)

type DeviceHandler struct {
	Log     *slog.Logger
	Sniffer *sniffer.Service
}

func NewDeviceHandler(log *slog.Logger, sniffer *sniffer.Service) *DeviceHandler {
	return &DeviceHandler{
		Log:     log,
		Sniffer: sniffer,
	}
}

func (h *DeviceHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := capture.ListDevices(h.Log)
	if err != nil {
		http.Error(w, "Failed to list devices: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(devices)
}

func (h *DeviceHandler) ChooseDevice(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Device string `json:"device"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	device, err := capture.ValidateDevice(req.Device, h.Log)
	if err != nil {
		http.Error(w, "Invalid device: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.Sniffer.SetDevice(req.Device); err != nil { //error Unresolved reference 'sniffer'
		http.Error(w, err.Error(), http.StatusBadRequest) //error Unresolved reference 'Error'
		return
	}

	// можно сохранить выбранное устройство в глобальный sniffer.Service
	// или в сессию, если планируешь поддержку нескольких пользователей
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Device selected: " + device))
}
