package toConsole

import (
	"fmt"
	"strings"

	"github.com/Vadym-H/GoSniffer/internal/sniffer/output"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ConsoleWriter struct {
	compact bool
}

func NewConsoleWriter(compact bool) output.PacketWriter {
	return &ConsoleWriter{compact: compact}
}

func (c *ConsoleWriter) WritePacket(packet gopacket.Packet, count int) {
	if c.compact {
		PrintPacketCompact(packet, count)
	} else {
		PrintPacket(packet, count)
	}
}

func (c *ConsoleWriter) Close() error {
	return nil // No cleanup needed for console
}

func PrintPacket(packet gopacket.Packet, count int) {
	fmt.Printf("\n=== Packet #%d ===\n", count)
	fmt.Printf("Timestamp: %s\n", packet.Metadata().Timestamp)
	fmt.Printf("Length: %d bytes\n", packet.Metadata().Length)

	// Ethernet Layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		fmt.Printf("Ethernet: %s -> %s (Type: %s)\n",
			eth.SrcMAC, eth.DstMAC, eth.EthernetType)
	}

	// IP Layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		fmt.Printf("IPv4: %s -> %s (Protocol: %s, TTL: %d)\n",
			ip.SrcIP, ip.DstIP, ip.Protocol, ip.TTL)
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		fmt.Printf("IPv6: %s -> %s (Protocol: %s, HopLimit: %d)\n",
			ip.SrcIP, ip.DstIP, ip.NextHeader, ip.HopLimit)
	}

	// TCP Layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		flags := getTCPFlags(tcp)
		fmt.Printf("TCP: %d -> %d [%s] Seq=%d Ack=%d Win=%d\n",
			tcp.SrcPort, tcp.DstPort, flags, tcp.Seq, tcp.Ack, tcp.Window)

		// Print payload if exists
		if len(tcp.Payload) > 0 {
			printPayload(tcp.Payload)
		}
	}

	// UDP Layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		fmt.Printf("UDP: %d -> %d (Length: %d)\n",
			udp.SrcPort, udp.DstPort, udp.Length)

		// Check for DNS
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			printDNS(dnsLayer.(*layers.DNS))
		} else if len(udp.Payload) > 0 {
			printPayload(udp.Payload)
		}
	}

	// ICMP Layer
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp := icmpLayer.(*layers.ICMPv4)
		fmt.Printf("ICMPv4: Type=%s Code=%d\n", icmp.TypeCode.Type(), icmp.TypeCode.Code())
	}

	// Application Layer
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()
		if len(payload) > 0 {
			// Try to detect HTTP
			if isHTTP(payload) {
				printHTTP(payload)
			}
		}
	}

	fmt.Println(strings.Repeat("-", 60))
}

func getTCPFlags(tcp *layers.TCP) string {
	var flags []string
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	if len(flags) == 0 {
		return "NONE"
	}
	return strings.Join(flags, ",")
}

func printPayload(payload []byte) {
	maxLen := 100
	if len(payload) > maxLen {
		fmt.Printf("Payload (%d bytes): %s...\n", len(payload), sanitize(payload[:maxLen]))
	} else {
		fmt.Printf("Payload (%d bytes): %s\n", len(payload), sanitize(payload))
	}
}

func printDNS(dns *layers.DNS) {
	fmt.Printf("DNS: ID=%d QR=%v OpCode=%s\n", dns.ID, dns.QR, dns.OpCode)

	// Questions
	if len(dns.Questions) > 0 {
		fmt.Println("  Questions:")
		for _, q := range dns.Questions {
			fmt.Printf("    %s (Type: %s, Class: %s)\n",
				string(q.Name), q.Type, q.Class)
		}
	}

	// Answers
	if len(dns.Answers) > 0 {
		fmt.Println("  Answers:")
		for _, a := range dns.Answers {
			fmt.Printf("    %s -> %s (TTL: %d)\n",
				string(a.Name), a.IP, a.TTL)
		}
	}
}

func isHTTP(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	httpMethods := []string{"GET ", "POST", "PUT ", "DELE", "HEAD", "OPTI", "PATC", "HTTP"}
	start := string(payload[:4])
	for _, method := range httpMethods {
		if start == method {
			return true
		}
	}
	return false
}

func printHTTP(payload []byte) {
	lines := strings.Split(string(payload), "\r\n")
	if len(lines) > 0 {
		fmt.Printf("HTTP: %s\n", lines[0])

		// Print headers (first 5)
		headerCount := 0
		for i := 1; i < len(lines) && headerCount < 5; i++ {
			if lines[i] == "" {
				break
			}
			fmt.Printf("  %s\n", lines[i])
			headerCount++
		}
	}
}

func sanitize(data []byte) string {
	result := make([]rune, 0, len(data))
	for _, b := range data {
		if b >= 32 && b <= 126 {
			result = append(result, rune(b))
		} else {
			result = append(result, '.')
		}
	}
	return string(result)
}

// Compact version for high-speed capture
func PrintPacketCompact(packet gopacket.Packet, count int) {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("#%d ", count))

	// IP info
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		sb.WriteString(fmt.Sprintf("%s->%s ", ip.SrcIP, ip.DstIP))
	}

	// Protocol and ports
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		sb.WriteString(fmt.Sprintf("TCP:%d->%d [%s] ", tcp.SrcPort, tcp.DstPort, getTCPFlags(tcp)))
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		sb.WriteString(fmt.Sprintf("UDP:%d->%d ", udp.SrcPort, udp.DstPort))
	}

	sb.WriteString(fmt.Sprintf("(%d bytes)", packet.Metadata().Length))

	fmt.Println(sb.String())
}
