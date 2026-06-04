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

// buildPacketData parses a packet into a PacketData struct. Called outside any lock.
func (w *JSONWriter) buildPacketData(pkt gopacket.Packet, count int) PacketData {
	data := PacketData{
		PacketNumber: count,
		Timestamp:    pkt.Metadata().Timestamp.Format("2006-01-02 15:04:05.000000"),
		Length:       len(pkt.Data()),
	}

	direction := "unknown"
	if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		data.SrcMAC = eth.SrcMAC.String()
		data.DstMAC = eth.DstMAC.String()
		data.EtherType = eth.EthernetType.String()
		switch {
		case eth.DstMAC.String() == "ff:ff:ff:ff:ff:ff":
			direction = "broadcast"
		case eth.SrcMAC.String() == w.interfaceMAC.String():
			direction = "outbound"
		case eth.DstMAC.String() == w.interfaceMAC.String():
			direction = "inbound"
		}
	}
	data.Direction = direction

	if ipv4Layer := pkt.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		data.SrcIP = ipv4.SrcIP.String()
		data.DstIP = ipv4.DstIP.String()
		data.Protocol = ipv4.Protocol.String()
		data.TTLHopLimit = fmt.Sprintf("%d", ipv4.TTL)
	} else if ipv6Layer := pkt.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)
		data.SrcIP = ipv6.SrcIP.String()
		data.DstIP = ipv6.DstIP.String()
		data.Protocol = ipv6.NextHeader.String()
		data.TTLHopLimit = fmt.Sprintf("%d", ipv6.HopLimit)
	}

	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		data.SrcPort = fmt.Sprintf("%d", tcp.SrcPort)
		data.DstPort = fmt.Sprintf("%d", tcp.DstPort)
		data.TCPFlags = formatTCPFlags(tcp)
		data.TCPSequence = fmt.Sprintf("%d", tcp.Seq)
		data.TCPAck = fmt.Sprintf("%d", tcp.Ack)
	} else if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		data.SrcPort = fmt.Sprintf("%d", udp.SrcPort)
		data.DstPort = fmt.Sprintf("%d", udp.DstPort)
	}

	return data
}

// WriteBatch marshals all packets outside the lock, then acquires the lock once
// to write the entire batch. This lets multiple workers marshal in parallel while
// only serializing on the actual file write.
func (w *JSONWriter) WriteBatch(packets []gopacket.Packet, startCount int) {
	type parsed struct {
		jsonBytes []byte
	}

	items := make([]parsed, 0, len(packets))
	for i, pkt := range packets {
		b, err := json.Marshal(w.buildPacketData(pkt, startCount+i))
		if err != nil {
			w.Log.Error("Failed to marshal packet to JSON", slog.String("error", err.Error()))
			continue
		}
		items = append(items, parsed{b})
	}

	if len(items) == 0 {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.Stopped || w.Writer == nil {
		return
	}
	if w.Duration > 0 && time.Since(w.StartTime) >= w.Duration {
		w.Stopped = true
		w.Cancel()
		return
	}

	for i, item := range items {
		// Comma before every entry except the very first packet written to the file.
		if !w.isFirstPacket || i > 0 {
			w.Writer.WriteByte(',')
		}
		w.Writer.WriteByte('\n')
		w.Writer.WriteString("    ")
		w.Writer.Write(item.jsonBytes)
		w.bytesWritten += int64(len(item.jsonBytes))
	}

	prev := w.packetCount
	w.packetCount += len(items)
	w.isFirstPacket = false

	if err := w.Writer.Flush(); err != nil {
		w.Log.Error("JSON writer flush error", slog.String("error", err.Error()))
	}

	if w.packetCount/1000 > prev/1000 {
		w.Log.Debug("Progress update",
			slog.Int("packets_written", w.packetCount),
			slog.Int64("bytes_written", w.bytesWritten),
			slog.Duration("elapsed", time.Since(w.StartTime)))
	}
}

func (w *JSONWriter) WritePacket(pkt gopacket.Packet, count int) {
	w.WriteBatch([]gopacket.Packet{pkt}, count)
}

func (w *JSONWriter) SupportsConcurrentWrites() bool {
	return true
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
