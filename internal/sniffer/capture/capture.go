package capture

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/Vadym-H/GoSniffer/internal/config"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/BpfFilter"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PacketStream struct {
	Packets chan gopacket.Packet
	Errors  chan error
	Stop    chan bool
}

type captureStats struct {
	packetCount int
	startTime   time.Time
	logInterval time.Duration
}

var BufferFullCount int = 0

func StartSniffing(device string, c *config.BpfFilters, log *slog.Logger) (*PacketStream, error) {
	const op = "capture.StartSniffing"
	log = log.With(slog.String("op", op))
	log.Info("Chosen device", slog.String("Chosen device", device))

	handle, err := openDevice(device, c, log)
	if err != nil {
		return nil, err
	}

	stream := newPacketStream()
	stats := &captureStats{
		startTime:   time.Now(),
		logInterval: 10 * time.Second,
	}

	go captureLoop(handle, stream, stats, log)

	return stream, nil
}

func openDevice(device string, c *config.BpfFilters, log *slog.Logger) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(device, 65536, false, pcap.BlockForever)
	if err != nil {
		log.Error("Capturing failed", err)
		return nil, fmt.Errorf("capturing failed: %w", err)
	}

	filter := bpfFilter.BuildBPFFilter(c)
	if filter == "" {
		handle.Close()
		return nil, fmt.Errorf("no BPF filter")
	}
	log.Info("BPF filter", slog.String("filter", filter))

	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	return handle, nil
}

func newPacketStream() *PacketStream {
	return &PacketStream{
		Packets: make(chan gopacket.Packet, 1000),
		Errors:  make(chan error, 10),
		Stop:    make(chan bool),
	}
}

func captureLoop(handle *pcap.Handle, stream *PacketStream, stats *captureStats, log *slog.Logger) {
	defer handle.Close()
	defer close(stream.Packets)
	defer close(stream.Errors)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-stream.Stop:
			return
		case packet := <-packetSource.Packets():
			stats.packetCount++
			handlePacket(packet, stream, stats, log)
			checkAndLogStats(stats, log)
		}
	}
}

func handlePacket(packet gopacket.Packet, stream *PacketStream, stats *captureStats, log *slog.Logger) {
	select {
	case stream.Packets <- packet:
		// Packet sent successfully
	default:
		BufferFullCount++
		log.Warn("Packet channel buffer full, packet lost!",
			slog.Int("bufferFullCount", BufferFullCount),
			slog.Int("packetCount", stats.packetCount))

		select {
		case stream.Errors <- fmt.Errorf("packet channel buffer full, packet lost"):
		default:
		}
	}
}

func checkAndLogStats(stats *captureStats, log *slog.Logger) {
	if time.Since(stats.startTime) >= stats.logInterval {
		speed := float64(stats.packetCount) / time.Since(stats.startTime).Seconds()
		log.Info("Capture speed",
			slog.Float64("pps", speed),
			slog.Int("bufferFullCount", BufferFullCount),
		)
		stats.packetCount = 0
		stats.startTime = time.Now()
	}
}

func ChoosingDevice(log *slog.Logger, deviceNum int) (string, error) {
	const op = "sniffer.ChoosingDevice"
	log = log.With(
		slog.String("op", op),
	)
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Error("ERROR: Failed to find network devices: %v", err)
		return "", err
	}

	// Display available devices
	fmt.Println("Available network devices:")
	for i, device := range devices {
		fmt.Printf("%d. %s", i, device.Name)
		if device.Description != "" {
			fmt.Printf(" (%s)", device.Description)
		}
		fmt.Println()

		// Show IP addresses for this device
		for _, address := range device.Addresses {
			fmt.Printf("   IP: %s\n", address.IP)
		}
	}

	if len(devices) == 0 {
		log.Warn("WARNING: No network devices found")
		return "", fmt.Errorf("no devices available")
	}
	device := devices[deviceNum].Name
	return device, nil
}
