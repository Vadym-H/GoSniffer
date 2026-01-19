package csvwriter

import (
	"context"
	"encoding/csv"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Vadym-H/GoSniffer/internal/sniffer/output"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/filemanager"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// CSVWriter implements the PacketWriter interface for CSV file output
// It supports time-based capture duration and graceful shutdown

type CSVWriter struct {
	File         *os.File
	Writer       *csv.Writer
	mu           sync.Mutex
	Log          *slog.Logger
	Ctx          context.Context
	Cancel       context.CancelFunc
	Stopped      bool
	StartTime    time.Time
	Duration     time.Duration
	Filename     string
	packetCount  int
	bytesWritten int64
	interfaceMAC net.HardwareAddr
}

func (w *CSVWriter) WritePacket(pkt gopacket.Packet, count int) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check if capture is stopped or expired
	if w.Stopped || w.Writer == nil {
		w.Log.Debug("Packet received but writer is stopped or nil", slog.Int("packet_count", count))
		return
	}

	// Check if duration has elapsed
	if w.Duration > 0 && time.Since(w.StartTime) >= w.Duration {
		w.Log.Warn("Capture duration reached, stopping writes",
			slog.Int("packets_written", w.packetCount),
			slog.Int64("bytes_written", w.bytesWritten),
			slog.Duration("elapsed", time.Since(w.StartTime)))
		w.Stopped = true
		w.Cancel()
		return
	}

	// Extract packet information
	packetSize := len(pkt.Data())
	timestamp := pkt.Metadata().Timestamp.Format("2006-01-02 15:04:05.000000")

	// Initialize row with basic info
	row := []string{
		fmt.Sprintf("%d", count),
		timestamp,
		fmt.Sprintf("%d", packetSize),
	}

	// Ethernet Layer - determine direction (outbound/inbound/broadcast/unknown)
	direction := "unknown"
	if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		row = append(row,
			eth.SrcMAC.String(),
			eth.DstMAC.String(),
			eth.EthernetType.String(),
		)

		// Determine direction based on MAC addresses
		dstMAC := eth.DstMAC.String()
		srcMAC := eth.SrcMAC.String()

		if dstMAC == "ff:ff:ff:ff:ff:ff" {
			direction = "broadcast"
		} else if srcMAC == w.interfaceMAC.String() {
			direction = "outbound"
		} else if dstMAC == w.interfaceMAC.String() {
			direction = "inbound"
		} else {
			direction = "unknown"
		}
	} else {
		row = append(row, "", "", "")
	}
	row = append(row, direction)

	// IP Layer
	var srcIP, dstIP, protocol, ttl string
	if ipv4Layer := pkt.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
		protocol = ipv4.Protocol.String()
		ttl = fmt.Sprintf("%d", ipv4.TTL)
	} else if ipv6Layer := pkt.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)
		srcIP = ipv6.SrcIP.String()
		dstIP = ipv6.DstIP.String()
		protocol = ipv6.NextHeader.String()
		ttl = fmt.Sprintf("%d", ipv6.HopLimit)
	}
	row = append(row, srcIP, dstIP, protocol, ttl)

	// TCP/UDP Layer
	var srcPort, dstPort, tcpFlags, tcpSeq, tcpAck string
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = fmt.Sprintf("%d", tcp.SrcPort)
		dstPort = fmt.Sprintf("%d", tcp.DstPort)
		tcpFlags = formatTCPFlags(tcp)
		tcpSeq = fmt.Sprintf("%d", tcp.Seq)
		tcpAck = fmt.Sprintf("%d", tcp.Ack)
	} else if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort = fmt.Sprintf("%d", udp.SrcPort)
		dstPort = fmt.Sprintf("%d", udp.DstPort)
	}
	row = append(row, srcPort, dstPort, tcpFlags, tcpSeq, tcpAck)

	// Write the row
	err := w.Writer.Write(row)
	if err != nil {
		w.Log.Error("Failed to write packet to CSV",
			slog.String("error", err.Error()),
			slog.Int("packet_count", count),
			slog.Int("packet_size", packetSize),
			slog.Int("total_packets_written", w.packetCount))
		return
	}

	w.packetCount++
	w.bytesWritten += int64(packetSize)

	// Flush every 100 packets to ensure data is written
	if w.packetCount%100 == 0 {
		w.Writer.Flush()
		if err := w.Writer.Error(); err != nil {
			w.Log.Error("CSV writer flush error",
				slog.String("error", err.Error()),
				slog.Int("packets_written", w.packetCount))
		}
	}

	// Log every 1000 packets
	if w.packetCount%1000 == 0 {
		w.Log.Debug("Progress update",
			slog.Int("packets_written", w.packetCount),
			slog.Int64("bytes_written", w.bytesWritten),
			slog.Duration("elapsed", time.Since(w.StartTime)))
	}
}

func (w *CSVWriter) SupportsConcurrentWrites() bool {
	return true // Safe with mutex protection
}

// Stop manually stops packet capture before duration expires
func (w *CSVWriter) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.Stopped {
		elapsed := time.Since(w.StartTime)
		avgPacketSize := int64(0)
		if w.packetCount > 0 {
			avgPacketSize = w.bytesWritten / int64(w.packetCount)
		}
		w.Log.Info("Manually stopping CSV writer",
			slog.String("filename", w.Filename),
			slog.Int("packets_written", w.packetCount),
			slog.Int64("bytes_written", w.bytesWritten),
			slog.Int64("avg_packet_size", avgPacketSize),
			slog.Duration("elapsed", elapsed))
		w.Stopped = true
		w.Cancel()
	} else {
		w.Log.Debug("CSV writer already stopped, ignoring Stop() call")
	}

	// Automatically close after stopping
	return w.closeInternal()
}

// Close closes the CSV writer and file handle
func (w *CSVWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closeInternal()
}

// NewCSVWriter creates a writer that captures for the specified duration.
// If duration is 0, it captures indefinitely until manually stopped via Stop().
// interfaceName is included in the filename (e.g., capture_wlo1.csv)
func NewCSVWriter(interfaceName string, duration time.Duration, log *slog.Logger, fm *filemanager.FileManager) (output.PacketWriter, error) {
	log.Debug("Initializing CSV writer",
		slog.String("interface", interfaceName),
		slog.Duration("duration", duration))

	// Get the network interface to retrieve its MAC address
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Error("Failed to get network interface",
			slog.String("interface", interfaceName),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to get interface %s: %w", interfaceName, err)
	}

	interfaceMAC := iface.HardwareAddr
	log.Debug("Network interface found",
		slog.String("interface", interfaceName),
		slog.String("MAC", interfaceMAC.String()))

	// Get file path from file manager (handles cleanup if needed)
	filename, err := fm.GetFilePath("csv")
	if err != nil {
		log.Error("Failed to get CSV file path from FileManager",
			slog.String("interface", interfaceName),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to get csv file path: %w", err)
	}

	log.Info("CSV file path generated",
		slog.String("filename", filename),
		slog.String("interface", interfaceName))

	// Create the output file
	file, err := os.Create(filename)
	if err != nil {
		log.Error("Failed to create CSV file",
			slog.String("filename", filename),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to create csv file: %w", err)
	}
	log.Debug("CSV file created successfully",
		slog.String("filename", filename))

	// Create the CSV writer
	writer := csv.NewWriter(file)

	// Write the CSV header
	headers := []string{
		"PacketNumber",
		"Timestamp",
		"Length",
		"SrcMAC",
		"DstMAC",
		"EtherType",
		"Direction",
		"SrcIP",
		"DstIP",
		"Protocol",
		"TTL/HopLimit",
		"SrcPort",
		"DstPort",
		"TCPFlags",
		"TCPSequence",
		"TCPAck",
	}

	if err := writer.Write(headers); err != nil {
		file.Close()
		log.Error("Failed to write CSV header",
			slog.String("filename", filename),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to write csv header: %w", err)
	}
	writer.Flush()

	if err := writer.Error(); err != nil {
		file.Close()
		log.Error("CSV writer error after header",
			slog.String("filename", filename),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("csv writer error: %w", err)
	}

	log.Debug("CSV file header written",
		slog.String("filename", filename))

	ctx, cancel := context.WithCancel(context.Background())
	startTime := time.Now()

	csvWriter := &CSVWriter{
		File:         file,
		Writer:       writer,
		Log:          log.With(slog.String("component", "csv-writer")),
		Ctx:          ctx,
		Cancel:       cancel,
		Stopped:      false,
		StartTime:    startTime,
		Duration:     duration,
		Filename:     filename,
		interfaceMAC: interfaceMAC,
	}

	if duration > 0 {
		csvWriter.Log.Info("CSV writer started",
			slog.Duration("duration", duration),
			slog.String("filename", filename),
			slog.Time("start_time", startTime))

		// Start a goroutine to auto-stop after duration
		go func() {
			timer := time.NewTimer(duration)
			defer timer.Stop()

			select {
			case <-timer.C:
				csvWriter.Log.Debug("Duration timer expired, auto-stopping capture")
				csvWriter.Stop()
			case <-ctx.Done():
				csvWriter.Log.Debug("Context cancelled, exiting duration timer goroutine")
				return
			}
		}()
	} else {
		csvWriter.Log.Info("CSV writer started",
			slog.String("filename", filename),
			slog.Time("start_time", startTime),
			slog.String("mode", "indefinite"))
	}

	return csvWriter, nil
}

// formatTCPFlags returns a string representation of TCP flags
func formatTCPFlags(tcp *layers.TCP) string {
	var flags string
	if tcp.FIN {
		flags += "F"
	}
	if tcp.SYN {
		flags += "S"
	}
	if tcp.RST {
		flags += "R"
	}
	if tcp.PSH {
		flags += "P"
	}
	if tcp.ACK {
		flags += "A"
	}
	if tcp.URG {
		flags += "U"
	}
	if flags == "" {
		flags = "NONE"
	}
	return flags
}
