package pcapwriter

import (
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output"
	"github.com/google/gopacket"
)

type PcapWriter struct{}

func (w *PcapWriter) Write(pkt gopacket.Packet) error {

}
func (w *PcapWriter) Close() error {

}
func (w *PcapWriter) SupportsConcurrentWrites() bool {
	return false
}

func NewPcapWriter() output.PacketWriter {
	return &PcapWriter{}
}
