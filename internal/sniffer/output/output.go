package output

import "github.com/google/gopacket"

// PacketWriter is an interface for different output methods
type PacketWriter interface {
	WritePacket(packet gopacket.Packet, count int)
	Close() error
	SupportsConcurrentWrites() bool
}
