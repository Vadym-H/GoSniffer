package bpfFilter

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/Vadym-H/GoSniffer/internal/config"
)

func BuildBPFFilter(f *config.BpfFilters) string {
	var parts []string

	// 1. Build protocol filter
	protocolFilter := BuildProtocolFilter(f)
	if protocolFilter != "" {
		parts = append(parts, protocolFilter)
	}

	// 2. Build IP filters
	if f.SrcIP != "" {
		parts = append(parts, fmt.Sprintf("src host %s", f.SrcIP))
	}
	if f.DstIP != "" {
		parts = append(parts, fmt.Sprintf("dst host %s", f.DstIP))
	}

	// 3. Build port filter
	portFilter := BuildPortFilter(f)
	if portFilter != "" {
		parts = append(parts, portFilter)
	}

	// Join with AND
	if len(parts) == 0 {
		return "" // No filter = capture all
	}

	return strings.Join(parts, " and ")
}

// BuildProtocolFilter creates the protocol part of BPF filter
func BuildProtocolFilter(f *config.BpfFilters) string {
	var protocols []string

	if f.Protocols.TCP {
		protocols = append(protocols, "tcp")
	}
	if f.Protocols.UDP {
		protocols = append(protocols, "udp")
	}
	if f.Protocols.ICMP {
		protocols = append(protocols, "icmp")
	}
	if f.Protocols.DNS {
		// DNS can be UDP or TCP on port 53
		protocols = append(protocols, "port 53")
	}

	if len(protocols) == 0 {
		return ""
	}

	// Wrap in parentheses if multiple protocols
	if len(protocols) == 1 {
		return protocols[0]
	}
	return fmt.Sprintf("(%s)", strings.Join(protocols, " or "))
}

// BuildPortFilter creates the port part of BPF filter
func BuildPortFilter(f *config.BpfFilters) string {
	if f.Ports == "" {
		return ""
	}

	// Parse comma-separated ports: "80,443,8080"
	portStrs := strings.Split(f.Ports, ",")
	var portFilters []string

	for _, portStr := range portStrs {
		portStr = strings.TrimSpace(portStr)
		if portStr == "" {
			continue
		}

		// Convert to int to validate
		if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 {
			portFilters = append(portFilters, fmt.Sprintf("port %d", port))
		} else {
			log.Printf("Warning: invalid port '%s', skipping", portStr)
		}
	}

	if len(portFilters) == 0 {
		return ""
	}

	// Wrap in parentheses if multiple ports
	if len(portFilters) == 1 {
		return portFilters[0]
	}
	return fmt.Sprintf("(%s)", strings.Join(portFilters, " or "))
}
