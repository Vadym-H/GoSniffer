package packets

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/Vadym-H/GoSniffer/internal/sniffer/processor/broadcaster"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/recording"
)

// StreamMetrics represents real-time packet stream and system metrics
type StreamMetrics struct {
	Timestamp int64 `json:"timestamp"`

	// Packet Metrics
	PacketsPerSecond int     `json:"packets_per_second"`
	TotalPackets     int64   `json:"total_packets"`
	DroppedPackets   int64   `json:"dropped_packets"`
	DropRate         float64 `json:"drop_rate_percent"` // percentage of dropped packets

	// Traffic Metrics
	BytesPerSecond    int64   `json:"bytes_per_second"`
	TotalBytes        int64   `json:"total_bytes"`
	MegabitsPerSecond float64 `json:"mbps"`

	// Peak & Averages (for capacity planning)
	PeakMetrics PeakMetrics `json:"peak_metrics"`

	// Protocol Distribution (if available from broadcaster)
	ProtocolStats *ProtocolStats `json:"protocol_stats,omitempty"`

	// Top Talkers (for network analysis)
	TopTalkers *TopTalkers `json:"top_talkers,omitempty"`

	// Buffer & Performance
	BufferUtilization int `json:"buffer_utilization"` // percentage, 0-100
	ActiveSubscribers int `json:"active_subscribers"`

	// System Health
	SystemMetrics SystemMetrics `json:"system_metrics"`

	// Sniffer Status
	SnifferStatus SnifferStatus `json:"sniffer_status"`

	// Storage & Disk
	StorageMetrics StorageMetrics `json:"storage_metrics"`

	// Error & Alert Tracking
	ErrorMetrics ErrorMetrics `json:"error_metrics"`
}

// ProtocolStats shows distribution of network protocols
type ProtocolStats struct {
	TCP   int64 `json:"tcp"`
	UDP   int64 `json:"udp"`
	ICMP  int64 `json:"icmp"`
	Other int64 `json:"other"`
}

// PeakMetrics tracks peak values for capacity planning
type PeakMetrics struct {
	PeakPPS        int     `json:"peak_pps"`        // Peak packets per second
	PeakMbps       float64 `json:"peak_mbps"`       // Peak throughput
	AvgPPS         int     `json:"avg_pps"`         // Average PPS over uptime
	AvgMbps        float64 `json:"avg_mbps"`        // Average Mbps over uptime
	PeakMemoryMB   uint64  `json:"peak_memory_mb"`  // Peak memory usage
	PeakGoroutines int     `json:"peak_goroutines"` // Peak goroutine count
}

// TopTalkers shows most active network endpoints
type TopTalkers struct {
	TopSourceIPs []IPTraffic   `json:"top_source_ips"`
	TopDestIPs   []IPTraffic   `json:"top_dest_ips"`
	TopPorts     []PortTraffic `json:"top_ports"`
}

type IPTraffic struct {
	IP          string `json:"ip"`
	PacketCount int64  `json:"packet_count"`
	ByteCount   int64  `json:"byte_count"`
}

type PortTraffic struct {
	Port        uint16 `json:"port"`
	PacketCount int64  `json:"packet_count"`
	Protocol    string `json:"protocol"` // TCP/UDP
}

// StorageMetrics for disk usage monitoring
type StorageMetrics struct {
	CaptureFileCount   int     `json:"capture_file_count"`
	TotalStorageUsedMB int64   `json:"total_storage_used_mb"`
	DiskSpaceFreeMB    int64   `json:"disk_space_free_mb"`
	DiskUsagePercent   float64 `json:"disk_usage_percent"`
	OldestCaptureAge   int64   `json:"oldest_capture_age_hours"` // hours
}

// ErrorMetrics for monitoring issues
type ErrorMetrics struct {
	TotalErrors      int64  `json:"total_errors"`
	ErrorsLastMinute int    `json:"errors_last_minute"`
	LastErrorTime    int64  `json:"last_error_time"`
	LastErrorMessage string `json:"last_error_message,omitempty"`
	CaptureErrors    int64  `json:"capture_errors"`    // Errors in packet capture
	ProcessingErrors int64  `json:"processing_errors"` // Errors in packet processing
}

// SystemMetrics provides system resource utilization
type SystemMetrics struct {
	MemoryUsageMB  uint64  `json:"memory_usage_mb"`
	MemoryAllocMB  uint64  `json:"memory_alloc_mb"`
	GoroutineCount int     `json:"goroutine_count"`
	CPUCores       int     `json:"cpu_cores"`
	GCPauseMs      float64 `json:"gc_pause_ms"`
}

// SnifferStatus provides sniffer information
type SnifferStatus struct {
	Uptime            int64  `json:"uptime_seconds"`
	Interface         string `json:"interface"`
	IsRecording       bool   `json:"is_recording"`
	IsMetricsEnabled  bool   `json:"is_metrics_enabled"`
	LastRestartTime   int64  `json:"last_restart_time,omitempty"`
	ConsecutiveErrors int    `json:"consecutive_errors"`
	FilterActive      bool   `json:"filter_active"`
}

// PacketStreamHandler handles packet stream endpoints
type PacketStreamHandler struct {
	log              *slog.Logger
	broadcaster      *broadcaster.PacketBroadcaster
	recordingService *recording.RecordingService
	capturesDir      string
	interfaceName    string
	startTime        time.Time

	// Track peaks for capacity planning
	peakPPS        int
	peakMbps       float64
	peakMemory     uint64
	peakGoroutines int

	// Track totals for averages
	totalSamples int64
	totalPPSSum  int64
	totalMbpsSum float64
}

// NewPacketStreamHandler creates a new packet stream handler
func NewPacketStreamHandler(log *slog.Logger, b *broadcaster.PacketBroadcaster, rs *recording.RecordingService, capturesDir string, interfaceName string) *PacketStreamHandler {
	return &PacketStreamHandler{
		log:              log,
		broadcaster:      b,
		recordingService: rs,
		capturesDir:      capturesDir,
		interfaceName:    interfaceName,
		startTime:        time.Now(),
	}
}

// SetBroadcaster sets the broadcaster reference
func (h *PacketStreamHandler) SetBroadcaster(b *broadcaster.PacketBroadcaster) {
	h.broadcaster = b
	h.startTime = time.Now() // Reset uptime when broadcaster is set
}

// SetInterfaceName sets the interface name for metrics
func (h *PacketStreamHandler) SetInterfaceName(name string) {
	h.interfaceName = name
}

// getStorageMetrics calculates current storage usage metrics
func (h *PacketStreamHandler) getStorageMetrics() StorageMetrics {
	metrics := StorageMetrics{}

	if h.capturesDir == "" {
		return metrics
	}

	// Count capture files and calculate total storage
	fileCount := 0
	totalSize := int64(0)
	oldestTime := int64(0)

	formats := []string{"pcap", "csv", "json"}
	for _, format := range formats {
		formatPath := filepath.Join(h.capturesDir, format)
		entries, err := os.ReadDir(formatPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				fileCount++
				fileInfo, err := entry.Info()
				if err == nil {
					totalSize += fileInfo.Size()
					modTime := fileInfo.ModTime().Unix()
					if oldestTime == 0 || modTime < oldestTime {
						oldestTime = modTime
					}
				}
			}
		}
	}

	// Get disk space info
	var stat syscall.Statfs_t
	if err := syscall.Statfs(h.capturesDir, &stat); err == nil {
		freeBlocks := int64(stat.Bavail)
		totalBlocks := int64(stat.Blocks)
		blockSize := int64(stat.Bsize)

		freeMB := (freeBlocks * blockSize) / (1024 * 1024)
		totalMB := (totalBlocks * blockSize) / (1024 * 1024)
		usedMB := totalMB - freeMB

		usagePercent := 0.0
		if totalMB > 0 {
			usagePercent = (float64(usedMB) / float64(totalMB)) * 100
		}

		metrics.DiskSpaceFreeMB = freeMB
		metrics.DiskUsagePercent = usagePercent
	}

	metrics.CaptureFileCount = fileCount
	metrics.TotalStorageUsedMB = totalSize / (1024 * 1024)

	// Calculate oldest capture age in hours
	if oldestTime > 0 {
		ageSeconds := time.Now().Unix() - oldestTime
		metrics.OldestCaptureAge = ageSeconds / 3600
	}

	return metrics
}

// isRecording checks if any recording format is currently recording
func (h *PacketStreamHandler) isRecording() bool {
	if h.recordingService == nil {
		return false
	}

	formats := []recording.RecordingFormat{
		recording.FormatPCAP,
		recording.FormatCSV,
		recording.FormatJSON,
	}

	for _, format := range formats {
		status := h.recordingService.GetStatus(format)
		if status.IsRecording {
			return true
		}
	}
	return false
}

// StreamMetrics handles SSE /sniffer/packets/stream
func (h *PacketStreamHandler) StreamMetrics(w http.ResponseWriter, r *http.Request) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	h.log.Info("New SSE metrics client connected")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Track for rate calculations
	var lastPacketCount int64 = 0
	var lastByteCount int64 = 0
	var lastGCPause uint64 = 0

	for {
		select {
		case <-ticker.C:
			currentPacketCount := h.broadcaster.GetPacketCount()
			currentDropped := h.broadcaster.GetDroppedPacketCount()
			currentBytes := h.broadcaster.GetTotalBytes() // You may need to add this method

			// Calculate rates
			pps := currentPacketCount - lastPacketCount
			bps := currentBytes - lastByteCount
			mbps := float64(bps*8) / 1_000_000 // Convert to Mbps

			lastPacketCount = currentPacketCount
			lastByteCount = currentBytes

			// Update peaks
			if int(pps) > h.peakPPS {
				h.peakPPS = int(pps)
			}
			if mbps > h.peakMbps {
				h.peakMbps = mbps
			}

			// Calculate drop rate
			var dropRate float64
			if currentPacketCount > 0 {
				dropRate = (float64(currentDropped) / float64(currentPacketCount+currentDropped)) * 100
			}

			// Get system metrics
			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			currentMemMB := m.Sys / 1024 / 1024
			currentGoroutines := runtime.NumGoroutine()

			if currentMemMB > h.peakMemory {
				h.peakMemory = currentMemMB
			}
			if currentGoroutines > h.peakGoroutines {
				h.peakGoroutines = currentGoroutines
			}

			gcPauseDelta := m.PauseTotalNs - lastGCPause
			lastGCPause = m.PauseTotalNs
			gcPauseMs := float64(gcPauseDelta) / 1_000_000

			// Calculate averages
			h.totalSamples++
			h.totalPPSSum += pps
			h.totalMbpsSum += mbps

			avgPPS := int(h.totalPPSSum / h.totalSamples)
			avgMbps := h.totalMbpsSum / float64(h.totalSamples)

			systemMetrics := SystemMetrics{
				MemoryUsageMB:  currentMemMB,
				MemoryAllocMB:  m.Alloc / 1024 / 1024,
				GoroutineCount: currentGoroutines,
				CPUCores:       runtime.NumCPU(),
				GCPauseMs:      gcPauseMs,
			}

			peakMetrics := PeakMetrics{
				PeakPPS:        h.peakPPS,
				PeakMbps:       h.peakMbps,
				AvgPPS:         avgPPS,
				AvgMbps:        avgMbps,
				PeakMemoryMB:   h.peakMemory,
				PeakGoroutines: h.peakGoroutines,
			}

			snifferStatus := SnifferStatus{
				Uptime:            int64(time.Since(h.startTime).Seconds()),
				Interface:         h.interfaceName,
				IsRecording:       h.isRecording(),
				IsMetricsEnabled:  true,
				ConsecutiveErrors: 0,     // Could be tracked separately
				FilterActive:      false, // TODO: Get from filter config if needed
			}

			// Get storage metrics from captures directory
			storageMetrics := h.getStorageMetrics()

			// Get error metrics from broadcaster
			totalErrs, captureErrs, procErrs, lastErrTime, lastErrMsg, errorsLastMin := h.broadcaster.GetErrorMetrics()
			errorMetrics := ErrorMetrics{
				TotalErrors:      totalErrs,
				ErrorsLastMinute: errorsLastMin,
				LastErrorTime:    lastErrTime,
				LastErrorMessage: lastErrMsg,
				CaptureErrors:    captureErrs,
				ProcessingErrors: procErrs,
			}

			// Build protocol stats (if broadcaster supports it)
			// var protocolStats *ProtocolStats
			// if stats := h.broadcaster.GetProtocolStats(); stats != nil {
			// 	protocolStats = &ProtocolStats{
			// 		TCP:   stats.TCP,
			// 		UDP:   stats.UDP,
			// 		ICMP:  stats.ICMP,
			// 		Other: stats.Other,
			// 	}
			// }

			metrics := StreamMetrics{
				Timestamp:         time.Now().Unix(),
				PacketsPerSecond:  int(pps),
				TotalPackets:      currentPacketCount,
				DroppedPackets:    currentDropped,
				DropRate:          dropRate,
				BytesPerSecond:    bps,
				TotalBytes:        currentBytes,
				MegabitsPerSecond: mbps,
				PeakMetrics:       peakMetrics,
				BufferUtilization: 0,                                  // TODO: Calculate from broadcaster buffer
				ActiveSubscribers: h.broadcaster.GetSubscriberCount(), // You may need to add this
				SystemMetrics:     systemMetrics,
				SnifferStatus:     snifferStatus,
				StorageMetrics:    storageMetrics,
				ErrorMetrics:      errorMetrics,
				// ProtocolStats:     protocolStats,
				// TopTalkers:        topTalkers,
			}

			data, err := json.Marshal(metrics)
			if err != nil {
				h.log.Error("Failed to marshal metrics", slog.String("error", err.Error()))
				return
			}

			w.Write([]byte("data: "))
			w.Write(data)
			w.Write([]byte("\n\n"))
			flusher.Flush()

		case <-r.Context().Done():
			h.log.Info("SSE metrics client disconnected")
			return
		}
	}
}
