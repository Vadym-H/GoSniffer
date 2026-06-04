package output

import "github.com/google/gopacket"

// PacketWriter is an interface for different output methods
type PacketWriter interface {
	WritePacket(packet gopacket.Packet, count int)
	// WriteBatch writes multiple packets under a single lock acquisition.
	// startCount is the packet number assigned to packets[0]; subsequent packets
	// are numbered startCount+1, startCount+2, etc.
	WriteBatch(packets []gopacket.Packet, startCount int)
	Close() error
	SupportsConcurrentWrites() bool
	Stop() error // Stop gracefully stops the writer (e.g., stops time-based capture)
}
