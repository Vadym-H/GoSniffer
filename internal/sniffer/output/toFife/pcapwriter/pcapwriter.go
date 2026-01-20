package pcapwriter

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/Vadym-H/GoSniffer/internal/sniffer/output"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/filemanager"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// PcapWriter implements the PacketWriter interface for PCAP file output
// It supports time-based capture duration and graceful shutdown

type PcapWriter struct {
	file         *os.File
	writer       *pcapgo.Writer
	mu           sync.Mutex
	log          *slog.Logger
	ctx          context.Context
	cancel       context.CancelFunc
	stopped      bool
	startTime    time.Time
	duration     time.Duration
	filename     string
	packetCount  int
	bytesWritten int64
}

func (w *PcapWriter) WritePacket(pkt gopacket.Packet, count int) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check if capture is stopped or expired
	if w.stopped || w.writer == nil {
		w.log.Debug("Packet received but writer is stopped or nil", slog.Int("packet_count", count))
		return
	}

	// Check if duration has elapsed
	if w.duration > 0 && time.Since(w.startTime) >= w.duration {
		w.log.Warn("Capture duration reached, stopping writes",
			slog.Int("packets_written", w.packetCount),
			slog.Int64("bytes_written", w.bytesWritten),
			slog.Duration("elapsed", time.Since(w.startTime)))
		w.stopped = true
		w.cancel()
		return
	}

	// Write the packet
	ci := pkt.Metadata().CaptureInfo
	packetSize := len(pkt.Data())
	err := w.writer.WritePacket(ci, pkt.Data())
	if err != nil {
		w.log.Error("Failed to write packet to PCAP",
			slog.String("error", err.Error()),
			slog.Int("packet_count", count),
			slog.Int("packet_size", packetSize),
			slog.Int("total_packets_written", w.packetCount))
		return
	}

	w.packetCount++
	w.bytesWritten += int64(packetSize)

	// Log every 1000 packets
	if w.packetCount%1000 == 0 {
		w.log.Debug("Progress update",
			slog.Int("packets_written", w.packetCount),
			slog.Int64("bytes_written", w.bytesWritten),
			slog.Duration("elapsed", time.Since(w.startTime)))
	}
}

func (w *PcapWriter) SupportsConcurrentWrites() bool {
	return false // PCAP format requires sequential writes to maintain integrity
}

// Stop manually stops packet capture before duration expires
func (w *PcapWriter) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.stopped {
		elapsed := time.Since(w.startTime)
		avgPacketSize := int64(0)
		if w.packetCount > 0 {
			avgPacketSize = w.bytesWritten / int64(w.packetCount)
		}
		w.log.Info("Manually stopping PCAP writer",
			slog.String("filename", w.filename),
			slog.Int("packets_written", w.packetCount),
			slog.Int64("bytes_written", w.bytesWritten),
			slog.Int64("avg_packet_size", avgPacketSize),
			slog.Duration("elapsed", elapsed))
		w.stopped = true
		w.cancel()
	} else {
		w.log.Debug("PCAP writer already stopped, ignoring Stop() call")
	}

	// Automatically close after stopping
	return w.closeInternal()
}

// Close closes the PCAP writer and file handle
func (w *PcapWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closeInternal()
}

// NewPcapWriter creates a writer that captures for the specified duration.
// If duration is 0, it captures indefinitely until manually stopped via Stop().
// interfaceName is included in the filename (e.g., capture_2024-01-15_14-30-25.pcap)
func NewPcapWriter(interfaceName string, duration time.Duration, log *slog.Logger, fm *filemanager.FileManager) (output.PacketWriter, error) {
	log.Debug("Initializing PCAP writer",
		slog.String("interface", interfaceName),
		slog.Duration("duration", duration))

	// Get file path from file manager (handles cleanup if needed)
	filename, err := fm.GetFilePath("pcap")
	if err != nil {
		log.Error("Failed to get PCAP file path from FileManager",
			slog.String("interface", interfaceName),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to get pcap file path: %w", err)
	}

	log.Info("PCAP file path generated",
		slog.String("filename", filename),
		slog.String("interface", interfaceName))

	// Create the output file
	file, err := os.Create(filename)
	if err != nil {
		log.Error("Failed to create PCAP file",
			slog.String("filename", filename),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to create pcap file: %w", err)
	}
	log.Debug("PCAP file created successfully",
		slog.String("filename", filename))

	// Create the pcap writer
	writer := pcapgo.NewWriter(file)

	// Write the PCAP file header
	// Parameters: snaplen (max bytes per packet), linkType
	if err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		file.Close()
		log.Error("Failed to write PCAP file header",
			slog.String("filename", filename),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to write pcap header: %w", err)
	}
	log.Debug("PCAP file header written",
		slog.String("filename", filename),
		slog.Int("snaplen", 65536),
		slog.String("link_type", "Ethernet"))

	ctx, cancel := context.WithCancel(context.Background())
	startTime := time.Now()

	pcapWriter := &PcapWriter{
		file:      file,
		writer:    writer,
		log:       log.With(slog.String("component", "pcap-writer")),
		ctx:       ctx,
		cancel:    cancel,
		stopped:   false,
		startTime: startTime,
		duration:  duration,
		filename:  filename,
	}

	if duration > 0 {
		pcapWriter.log.Info("PCAP writer started",
			slog.Duration("duration", duration),
			slog.String("filename", filename),
			slog.Time("start_time", startTime))

		// Start a goroutine to auto-stop after duration
		go func() {
			timer := time.NewTimer(duration)
			defer timer.Stop()

			select {
			case <-timer.C:
				pcapWriter.log.Debug("Duration timer expired, auto-stopping capture")
				pcapWriter.Stop()
			case <-ctx.Done():
				pcapWriter.log.Debug("Context cancelled, exiting duration timer goroutine")
				return
			}
		}()
	} else {
		pcapWriter.log.Info("PCAP writer started",
			slog.String("filename", filename),
			slog.Time("start_time", startTime),
			slog.String("mode", "indefinite"))
	}

	return pcapWriter, nil
}
