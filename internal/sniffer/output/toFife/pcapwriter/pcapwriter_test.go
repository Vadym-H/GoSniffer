package pcapwriter

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/filemanager"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TestStopNonBlocking tests that Stop() doesn't block indefinitely
func TestStopNonBlocking(t *testing.T) {
	// Create logger
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create file manager
	fm, err := filemanager.NewFileManager(log)
	if err != nil {
		t.Fatalf("Failed to create file manager: %v", err)
	}

	// Create PCAP writer
	writer, err := NewPcapWriter("lo", 0, log, fm)
	if err != nil {
		t.Fatalf("Failed to create PCAP writer: %v", err)
	}

	// Run Stop() in a goroutine with a timeout
	done := make(chan bool)
	go func() {
		writer.Stop()
		done <- true
	}()

	// Wait with timeout
	select {
	case <-done:
		t.Log("Stop() completed successfully")
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() took too long, potential deadlock")
	}

	// Cleanup
	writer.Close()
}

// TestStopWithConcurrentWrites tests Stop() while packets are being written
func TestStopWithConcurrentWrites(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create file manager
	fm, err := filemanager.NewFileManager(log)
	if err != nil {
		t.Fatalf("Failed to create file manager: %v", err)
	}

	writer, err := NewPcapWriter("lo", 0, log, fm)
	if err != nil {
		t.Fatalf("Failed to create PCAP writer: %v", err)
	}

	// Create a mock packet
	testPacket := createMockPacket()

	// Simulate concurrent writes
	stopWriting := make(chan bool)
	go func() {
		for i := 0; i < 100; i++ {
			select {
			case <-stopWriting:
				return
			default:
				writer.WritePacket(testPacket, i)
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	// Give it time to write a few packets
	time.Sleep(10 * time.Millisecond)

	// Try to stop in a separate goroutine with timeout
	done := make(chan bool)
	go func() {
		writer.Stop()
		done <- true
	}()

	select {
	case <-done:
		t.Log("Stop() completed without blocking")
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() blocked, potential deadlock detected")
	}

	close(stopWriting)
	writer.Close()
}

// TestNonBlockingClose tests that Close() doesn't block
func TestNonBlockingClose(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create file manager
	fm, err := filemanager.NewFileManager(log)
	if err != nil {
		t.Fatalf("Failed to create file manager: %v", err)
	}

	writer, err := NewPcapWriter("lo", 0, log, fm)
	if err != nil {
		t.Fatalf("Failed to create PCAP writer: %v", err)
	}

	done := make(chan bool)
	go func() {
		writer.Close()
		done <- true
	}()

	select {
	case <-done:
		t.Log("Close() completed successfully")
	case <-time.After(2 * time.Second):
		t.Fatal("Close() took too long, potential deadlock")
	}
}

// Helper function to create a mock packet
func createMockPacket() gopacket.Packet {
	// Create a simple Ethernet packet
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0, 1, 2, 3, 4, 5},
		DstMAC:       []byte{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create IP layer
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
	}

	// Create TCP layer
	tcp := &layers.TCP{
		SrcPort: 1234,
		DstPort: 80,
		Seq:     1000,
		Ack:     2000,
	}

	// Build packet
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte("test")))

	return gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
}

// TestStopWithDurationExpired tests Stop() behavior when duration expires
func TestStopWithDurationExpired(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create file manager
	fm, err := filemanager.NewFileManager(log)
	if err != nil {
		t.Fatalf("Failed to create file manager: %v", err)
	}

	// Create writer with 100ms duration
	writer, err := NewPcapWriter("lo", 100*time.Millisecond, log, fm)
	if err != nil {
		t.Fatalf("Failed to create PCAP writer: %v", err)
	}

	testPacket := createMockPacket()

	// Write packets for 50ms
	writesDone := make(chan bool)
	go func() {
		for i := 0; i < 200; i++ {
			writer.WritePacket(testPacket, i)
			time.Sleep(1 * time.Millisecond)
		}
		writesDone <- true
	}()

	// Wait for writes to complete
	<-writesDone

	// Close should complete quickly even after duration expired
	done := make(chan bool)
	go func() {
		writer.Close()
		done <- true
	}()

	select {
	case <-done:
		t.Log("Close() completed after duration expiry")
	case <-time.After(2 * time.Second):
		t.Fatal("Close() blocked after duration expiry")
	}
}
