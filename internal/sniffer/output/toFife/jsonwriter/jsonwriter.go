package jsonwriter

import (
	"bufio"
	"context"
	"encoding/json"
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

// PacketData represents a single packet in JSON format
type PacketData struct {
	PacketNumber int    `json:"packet_number"`
	Timestamp    string `json:"timestamp"`
	Length       int    `json:"length"`
	SrcMAC       string `json:"src_mac"`
	DstMAC       string `json:"dst_mac"`
	EtherType    string `json:"ether_type"`
	Direction    string `json:"direction"`
	SrcIP        string `json:"src_ip"`
	DstIP        string `json:"dst_ip"`
	Protocol     string `json:"protocol"`
	TTLHopLimit  string `json:"ttl_hop_limit"`
	SrcPort      string `json:"src_port"`
	DstPort      string `json:"dst_port"`
	TCPFlags     string `json:"tcp_flags"`
	TCPSequence  string `json:"tcp_sequence"`
	TCPAck       string `json:"tcp_ack"`
}

// JSONWriter implements the PacketWriter interface for JSON file output
// It supports time-based capture duration and graceful shutdown
// Writes packets as a proper JSON array format
type JSONWriter struct {
	File          *os.File
	Writer        *bufio.Writer
	mu            sync.Mutex
	Log           *slog.Logger
	Ctx           context.Context
	Cancel        context.CancelFunc
	Stopped       bool
	StartTime     time.Time
	Duration      time.Duration
	Filename      string
	packetCount   int
	bytesWritten  int64
	interfaceMAC  net.HardwareAddr
	isFirstPacket bool
}

func (w *JSONWriter) WritePacket(pkt gopacket.Packet, count int) {
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

	packetData := PacketData{
		PacketNumber: count,
		Timestamp:    timestamp,
		Length:       packetSize,
	}

	// Ethernet Layer - determine direction (outbound/inbound/broadcast/unknown)
	direction := "unknown"
	if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		packetData.SrcMAC = eth.SrcMAC.String()
		packetData.DstMAC = eth.DstMAC.String()
		packetData.EtherType = eth.EthernetType.String()

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
	}
	packetData.Direction = direction

	// IP Layer
	if ipv4Layer := pkt.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		packetData.SrcIP = ipv4.SrcIP.String()
		packetData.DstIP = ipv4.DstIP.String()
		packetData.Protocol = ipv4.Protocol.String()
		packetData.TTLHopLimit = fmt.Sprintf("%d", ipv4.TTL)
	} else if ipv6Layer := pkt.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)
		packetData.SrcIP = ipv6.SrcIP.String()
		packetData.DstIP = ipv6.DstIP.String()
		packetData.Protocol = ipv6.NextHeader.String()
		packetData.TTLHopLimit = fmt.Sprintf("%d", ipv6.HopLimit)
	}

	// TCP/UDP Layer
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		packetData.SrcPort = fmt.Sprintf("%d", tcp.SrcPort)
		packetData.DstPort = fmt.Sprintf("%d", tcp.DstPort)
		packetData.TCPFlags = formatTCPFlags(tcp)
		packetData.TCPSequence = fmt.Sprintf("%d", tcp.Seq)
		packetData.TCPAck = fmt.Sprintf("%d", tcp.Ack)
	} else if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		packetData.SrcPort = fmt.Sprintf("%d", udp.SrcPort)
		packetData.DstPort = fmt.Sprintf("%d", udp.DstPort)
	}

	// Marshal to JSON and write
	jsonBytes, err := json.Marshal(packetData)
	if err != nil {
		w.Log.Error("Failed to marshal packet to JSON",
			slog.String("error", err.Error()),
			slog.Int("packet_count", count))
		return
	}

	// Write comma separator (except for first packet)
	if !w.isFirstPacket {
		err = w.Writer.WriteByte(',')
		if err != nil {
			w.Log.Error("Failed to write comma separator to JSON",
				slog.String("error", err.Error()),
				slog.Int("packet_count", count))
			return
		}
	}

	// Write newline before object for formatting
	err = w.Writer.WriteByte('\n')
	if err != nil {
		w.Log.Error("Failed to write newline before JSON object",
			slog.String("error", err.Error()),
			slog.Int("packet_count", count))
		return
	}

	// Write indentation
	_, err = w.Writer.WriteString("    ")
	if err != nil {
		w.Log.Error("Failed to write indentation to JSON",
			slog.String("error", err.Error()),
			slog.Int("packet_count", count))
		return
	}

	// Write JSON object
	_, err = w.Writer.Write(jsonBytes)
	if err != nil {
		w.Log.Error("Failed to write packet to JSON",
			slog.String("error", err.Error()),
			slog.Int("packet_count", count),
			slog.Int("packet_size", packetSize),
			slog.Int("total_packets_written", w.packetCount))
		return
	}

	w.packetCount++
	w.bytesWritten += int64(len(jsonBytes))
	w.isFirstPacket = false

	// Flush every 100 packets to ensure data is written
	if w.packetCount%100 == 0 {
		err := w.Writer.Flush()
		if err != nil {
			w.Log.Error("JSON writer flush error",
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

func (w *JSONWriter) SupportsConcurrentWrites() bool {
	return true // Safe with mutex protection
}

// Stop manually stops packet capture before duration expires
func (w *JSONWriter) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.Stopped {
		elapsed := time.Since(w.StartTime)
		avgPacketSize := int64(0)
		if w.packetCount > 0 {
			avgPacketSize = w.bytesWritten / int64(w.packetCount)
		}
		w.Log.Info("Manually stopping JSON writer",
			slog.String("filename", w.Filename),
			slog.Int("packets_written", w.packetCount),
			slog.Int64("bytes_written", w.bytesWritten),
			slog.Int64("avg_packet_size", avgPacketSize),
			slog.Duration("elapsed", elapsed))
		w.Stopped = true
		w.Cancel()
	} else {
		w.Log.Debug("JSON writer already stopped, ignoring Stop() call")
	}

	// Automatically close after stopping
	return w.closeInternal()
}

// Close closes the JSON writer and file handle
func (w *JSONWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closeInternal()
}

// NewJSONWriter creates a writer that captures for the specified duration.
// If duration is 0, it captures indefinitely until manually stopped via Stop().
// interfaceName is included in the filename (e.g., capture_wlo1.json)
// Output format is JSONL (JSON Lines): one JSON object per line
func NewJSONWriter(interfaceName string, duration time.Duration, log *slog.Logger, fm *filemanager.FileManager) (output.PacketWriter, error) {
	log.Debug("Initializing JSON writer",
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
	filename, err := fm.GetFilePath("json")
	if err != nil {
		log.Error("Failed to get JSON file path from FileManager",
			slog.String("interface", interfaceName),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to get json file path: %w", err)
	}

	log.Info("JSON file path generated",
		slog.String("filename", filename),
		slog.String("interface", interfaceName))

	// Create the output file
	file, err := os.Create(filename)
	if err != nil {
		log.Error("Failed to create JSON file",
			slog.String("filename", filename),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to create json file: %w", err)
	}
	log.Debug("JSON file created successfully",
		slog.String("filename", filename))

	// Create buffered writer
	writer := bufio.NewWriter(file)

	// Write opening bracket for JSON array
	_, err = writer.WriteString("[")
	if err != nil {
		log.Error("Failed to write opening bracket to JSON",
			slog.String("filename", filename),
			slog.String("error", err.Error()))
		file.Close()
		return nil, fmt.Errorf("failed to write opening bracket: %w", err)
	}

	log.Debug("JSON file initialized",
		slog.String("filename", filename),
		slog.String("format", "JSON array"))

	ctx, cancel := context.WithCancel(context.Background())
	startTime := time.Now()

	jsonWriter := &JSONWriter{
		File:          file,
		Writer:        writer,
		Log:           log.With(slog.String("component", "json-writer")),
		Ctx:           ctx,
		Cancel:        cancel,
		Stopped:       false,
		StartTime:     startTime,
		Duration:      duration,
		Filename:      filename,
		interfaceMAC:  interfaceMAC,
		isFirstPacket: true,
	}

	if duration > 0 {
		jsonWriter.Log.Info("JSON writer started",
			slog.Duration("duration", duration),
			slog.String("filename", filename),
			slog.Time("start_time", startTime))

		// Start a goroutine to auto-stop after duration
		go func() {
			timer := time.NewTimer(duration)
			defer timer.Stop()

			select {
			case <-timer.C:
				jsonWriter.Log.Debug("Duration timer expired, auto-stopping capture")
				jsonWriter.Stop()
			case <-ctx.Done():
				jsonWriter.Log.Debug("Context cancelled, exiting duration timer goroutine")
				return
			}
		}()
	} else {
		jsonWriter.Log.Info("JSON writer started",
			slog.Time("start_time", startTime),
			slog.String("mode", "indefinite"))
	}

	return jsonWriter, nil
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
