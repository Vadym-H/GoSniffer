package pcapwriter

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// closeInternal handles the actual cleanup logic
// Must be called with the mutex already locked
func (w *PcapWriter) closeInternal() error {
	w.stopped = true
	w.cancel()

	if w.file != nil {
		elapsed := time.Since(w.startTime)
		avgPacketSize := int64(0)
		packetsPerSec := float64(0)

		if w.packetCount > 0 {
			avgPacketSize = w.bytesWritten / int64(w.packetCount)
		}

		if elapsed.Seconds() > 0 {
			packetsPerSec = float64(w.packetCount) / elapsed.Seconds()
		}

		// Sync to ensure all data is written to disk
		if err := w.file.Sync(); err != nil {
			w.log.Error("Failed to sync PCAP file to disk",
				slog.String("filename", w.filename),
				slog.String("error", err.Error()))
		} else {
			w.log.Debug("PCAP file synced to disk successfully",
				slog.String("filename", w.filename))
		}

		w.log.Info("Closing PCAP file",
			slog.String("filename", w.filename),
			slog.Int("total_packets", w.packetCount),
			slog.Int64("total_bytes", w.bytesWritten),
			slog.Int64("avg_packet_size", avgPacketSize),
			slog.Float64("packets_per_sec", packetsPerSec),
			slog.Duration("total_duration", elapsed))

		if err := w.file.Close(); err != nil {
			w.log.Error("Failed to close PCAP file",
				slog.String("filename", w.filename),
				slog.String("error", err.Error()))
			return fmt.Errorf("failed to close PCAP file: %w", err)
		}
		w.log.Debug("PCAP file handle closed",
			slog.String("filename", w.filename))
		w.file = nil
		w.writer = nil
	}
	// Silently return if file is already closed (not an error condition)
	return nil
}

// GetContext returns the writer's context (useful for monitoring expiration)
func (w *PcapWriter) GetContext() context.Context {
	return w.ctx
}

// GetStats returns current statistics
// Returns: packets written, bytes written, elapsed time
func (w *PcapWriter) GetStats() (packets int, bytes int64, elapsed time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.packetCount, w.bytesWritten, time.Since(w.startTime)
}
