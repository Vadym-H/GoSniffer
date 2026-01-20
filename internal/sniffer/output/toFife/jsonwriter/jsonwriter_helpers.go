package jsonwriter

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// closeInternal handles the actual cleanup logic
// Must be called with the mutex already locked
func (w *JSONWriter) closeInternal() error {
	w.Stopped = true
	w.Cancel()

	if w.File != nil {
		elapsed := time.Since(w.StartTime)
		avgPacketSize := int64(0)
		packetsPerSec := float64(0)

		if w.packetCount > 0 {
			avgPacketSize = w.bytesWritten / int64(w.packetCount)
		}

		if elapsed.Seconds() > 0 {
			packetsPerSec = float64(w.packetCount) / elapsed.Seconds()
		}

		// Write closing bracket and newline to complete the JSON array
		_, err := w.Writer.WriteString("\n]\n")
		if err != nil {
			w.Log.Error("Failed to write closing bracket to JSON",
				slog.String("filename", w.Filename),
				slog.String("error", err.Error()))
		}

		// Flush any remaining data
		err = w.Writer.Flush()
		if err != nil {
			w.Log.Error("Failed to flush JSON writer",
				slog.String("filename", w.Filename),
				slog.String("error", err.Error()))
		} else {
			w.Log.Debug("JSON writer flushed successfully",
				slog.String("filename", w.Filename))
		}

		// Sync to ensure all data is written to disk
		if err := w.File.Sync(); err != nil {
			w.Log.Error("Failed to sync JSON file to disk",
				slog.String("filename", w.Filename),
				slog.String("error", err.Error()))
		} else {
			w.Log.Debug("JSON file synced to disk successfully",
				slog.String("filename", w.Filename))
		}

		w.Log.Info("Closing JSON file",
			slog.String("filename", w.Filename),
			slog.Int("total_packets", w.packetCount),
			slog.Int64("total_bytes", w.bytesWritten),
			slog.Int64("avg_packet_size", avgPacketSize),
			slog.Float64("packets_per_sec", packetsPerSec),
			slog.Duration("total_duration", elapsed))

		if err := w.File.Close(); err != nil {
			w.Log.Error("Failed to close JSON file",
				slog.String("filename", w.Filename),
				slog.String("error", err.Error()))
			return fmt.Errorf("failed to close JSON file: %w", err)
		}
		w.Log.Debug("JSON file handle closed",
			slog.String("filename", w.Filename))
		w.File = nil
		w.Writer = nil
	}
	// Silently return if file is already closed (not an error condition)
	return nil
}

// GetContext returns the writer's context (useful for monitoring expiration)
func (w *JSONWriter) GetContext() context.Context {
	return w.Ctx
}

// GetStats returns current statistics
// Returns: packets written, bytes written, elapsed time
func (w *JSONWriter) GetStats() (packets int, bytes int64, elapsed time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.packetCount, w.bytesWritten, time.Since(w.StartTime)
}
