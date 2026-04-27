package sniffer

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Vadym-H/GoSniffer/internal/metrics"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// MetricsAggregator collects packet metrics for Prometheus export
// Runs as a single goroutine (no workers needed - pure in-memory updates)
type MetricsAggregator struct {
	collector  *metrics.MetricsCollector
	log        *slog.Logger
	mu         sync.Mutex
	stopChan   chan struct{}
	packetChan chan gopacket.Packet
	stream     *capture.PacketStream
	wg         sync.WaitGroup
	running    atomic.Bool
	interface_ string

	// Stateful tracking for TCP connections
	tcpConnections map[string]*tcpConnectionState // key: "srcIP:srcPort:dstIP:dstPort"
	connMu         sync.RWMutex

	// Sliding window for unique IPs (1-minute)
	uniqueSrcIPs  map[string]time.Time // key: IP, value: last seen time
	uniqueDstIPs  map[string]time.Time
	ipMu          sync.RWMutex
	lastIPCleanup time.Time

	// Bandwidth tracking (10-second window)
	bytesIn10s atomic.Int64
	lastBWCalc time.Time
	bwMu       sync.RWMutex

	// Track gauge labels for cleanup
	previousGaugeLabels map[string]bool
}

// TCP connection state tracking
type tcpConnectionState struct {
	lastSeen time.Time
	state    string // "syn_sent", "established", "fin_wait", etc.
	dstPort  string
	srcIP    string
	dstIP    string
}

// wellKnownPorts defines which ports to track individually
var wellKnownPorts = map[string]bool{
	"80":    true, // HTTP
	"443":   true, // HTTPS
	"22":    true, // SSH
	"53":    true, // DNS
	"3306":  true, // MySQL
	"5432":  true, // PostgreSQL
	"6379":  true, // Redis
	"8080":  true, // HTTP alt
	"27017": true, // MongoDB
	"3389":  true, // RDP
}

// normalizePort returns the port if it's well-known, otherwise "other"
// This prevents cardinality explosion in Prometheus metrics
func normalizePort(port string) string {
	if wellKnownPorts[port] {
		return port
	}
	return "other"
}

// NewMetricsAggregator creates a new metrics aggregator
func NewMetricsAggregator(interfaceName string, collector *metrics.MetricsCollector, log *slog.Logger) *MetricsAggregator {
	return &MetricsAggregator{
		collector:           collector,
		log:                 log.With(slog.String("component", "metrics_aggregator")),
		stopChan:            make(chan struct{}),
		interface_:          interfaceName,
		tcpConnections:      make(map[string]*tcpConnectionState),
		uniqueSrcIPs:        make(map[string]time.Time),
		uniqueDstIPs:        make(map[string]time.Time),
		lastIPCleanup:       time.Now(),
		lastBWCalc:          time.Now(),
		previousGaugeLabels: make(map[string]bool),
	}
}

// Start begins processing packets from the channel (single goroutine)
func (ma *MetricsAggregator) Start(packetChan chan gopacket.Packet, stream *capture.PacketStream) {
	const op = "sniffer.MetricsAggregator.Start"
	log := ma.log.With(slog.String("op", op))

	ma.packetChan = packetChan
	ma.stream = stream
	ma.running.Store(true)

	log.Info("Starting metrics aggregator", slog.String("interface", ma.interface_))
	ma.collector.CaptureActive.WithLabelValues(ma.interface_).Set(1)

	// Single worker goroutine (no parallelism needed)
	ma.wg.Add(1)
	go ma.worker()
}

// worker processes packets from the channel (single goroutine)
func (ma *MetricsAggregator) worker() {
	const op = "sniffer.MetricsAggregator.worker"
	log := ma.log.With(slog.String("op", op))
	defer ma.wg.Done()

	log.Info("Metrics aggregator worker started")

	for {
		select {
		case <-ma.stopChan:
			log.Info("Metrics aggregator worker stopping")
			return
		case packet, ok := <-ma.packetChan:
			if !ok {
				log.Info("Packet channel closed, worker stopping")
				return
			}
			ma.processPacket(packet)
		}
	}
}

// processPacket extracts metrics from a packet
func (ma *MetricsAggregator) processPacket(packet gopacket.Packet) {
	// Get packet size for bandwidth tracking
	packetSize := int64(packet.Metadata().Length)
	ma.bytesIn10s.Add(packetSize)

	// Periodic bandwidth calculation
	now := time.Now()
	ma.bwMu.Lock()
	elapsed := now.Sub(ma.lastBWCalc).Seconds()
	if elapsed >= 10.0 {
		bytes := ma.bytesIn10s.Swap(0)
		bps := float64(bytes) / elapsed
		ma.collector.BandwidthBytesPerSecond.WithLabelValues(ma.interface_, "rx").Set(bps)
		ma.lastBWCalc = now
	}
	ma.bwMu.Unlock()

	// Clean up old IPs and stale connections every 30 seconds
	if now.Sub(ma.lastIPCleanup) > 30*time.Second {
		ma.cleanupOldIPs(now)
		ma.cleanupStaleConnections(now)
	}

	// Process network layers
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
	}

	if ipLayer != nil {
		if ipv4, ok := ipLayer.(*layers.IPv4); ok {
			ma.recordIPMetrics(ipv4.SrcIP.String(), ipv4.DstIP.String())
			ma.processL4(ipv4.Protocol, packet)
		} else if ipv6, ok := ipLayer.(*layers.IPv6); ok {
			ma.recordIPMetrics(ipv6.SrcIP.String(), ipv6.DstIP.String())
			ma.processL4IPv6(ipv6.NextHeader, packet)
		}
	}
}

// processL4 processes Layer 4 protocols (TCP, UDP, ICMP)
func (ma *MetricsAggregator) processL4(protocol layers.IPProtocol, packet gopacket.Packet) {
	switch protocol {
	case layers.IPProtocolTCP:
		ma.processTCP(packet)
	case layers.IPProtocolUDP:
		ma.processUDP(packet)
	case layers.IPProtocolICMPv4:
		ma.processICMPv4(packet)
	}
}

// processL4IPv6 processes Layer 4 for IPv6
func (ma *MetricsAggregator) processL4IPv6(nextHeader layers.IPProtocol, packet gopacket.Packet) {
	switch nextHeader {
	case layers.IPProtocolTCP:
		ma.processTCP(packet)
	case layers.IPProtocolUDP:
		ma.processUDP(packet)
	case layers.IPProtocolICMPv6:
		ma.processICMPv6(packet)
	}
}

// processTCP handles TCP metrics
func (ma *MetricsAggregator) processTCP(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp := tcpLayer.(*layers.TCP)
	dstPort := tcp.DstPort.String()
	normalizedPort := normalizePort(dstPort) // Normalize for metrics labels

	// Track TCP flags with normalized port
	if tcp.SYN {
		ma.collector.TCPFlagsTotal.WithLabelValues(ma.interface_, "syn", normalizedPort).Inc()
		ma.recordTCPConnection(packet, "syn_sent", dstPort)
	}
	if tcp.ACK {
		ma.collector.TCPFlagsTotal.WithLabelValues(ma.interface_, "ack", normalizedPort).Inc()
		ma.recordTCPConnection(packet, "established", dstPort)
	}
	if tcp.FIN {
		ma.collector.TCPFlagsTotal.WithLabelValues(ma.interface_, "fin", normalizedPort).Inc()
		ma.recordTCPClosed(packet, "fin", dstPort)
	}
	if tcp.RST {
		ma.collector.TCPFlagsTotal.WithLabelValues(ma.interface_, "rst", normalizedPort).Inc()
		ma.collector.TCPResetsTotal.WithLabelValues(ma.interface_, normalizedPort).Inc()
		ma.recordTCPClosed(packet, "rst", dstPort)
	}

	// Record total TCP packet
	ma.collector.PacketsTotal.WithLabelValues(ma.interface_, "tcp").Inc()
	ma.collector.BytesTotal.WithLabelValues(ma.interface_, "tcp").Add(float64(len(packet.Data())))
}

// recordTCPConnection tracks TCP connection state
func (ma *MetricsAggregator) recordTCPConnection(packet gopacket.Packet, state string, dstPort string) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil || ipLayer == nil {
		return
	}

	tcp := tcpLayer.(*layers.TCP)
	var srcIP, dstIP string

	if ipv4, ok := ipLayer.(*layers.IPv4); ok {
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
	} else if ipv6, ok := ipLayer.(*layers.IPv6); ok {
		srcIP = ipv6.SrcIP.String()
		dstIP = ipv6.DstIP.String()
	} else {
		return
	}

	connKey := srcIP + ":" + tcp.SrcPort.String() + ":" + dstIP + ":" + dstPort

	ma.connMu.Lock()
	defer ma.connMu.Unlock()

	normalizedPort := normalizePort(dstPort)
	if _, exists := ma.tcpConnections[connKey]; !exists {
		// New connection - use normalized port for metrics
		ma.collector.TCPConnectionsOpenedTotal.WithLabelValues(ma.interface_, normalizedPort).Inc()
	}

	ma.tcpConnections[connKey] = &tcpConnectionState{
		lastSeen: time.Now(),
		state:    state,
		dstPort:  dstPort, // Keep actual port internally
		srcIP:    srcIP,
		dstIP:    dstIP,
	}

	// Update active connections gauge
	ma.updateActiveConnectionsGauge()
}

// recordTCPClosed tracks closed TCP connections
func (ma *MetricsAggregator) recordTCPClosed(packet gopacket.Packet, reason string, dstPort string) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil || ipLayer == nil {
		return
	}

	tcp := tcpLayer.(*layers.TCP)
	var srcIP, dstIP string

	if ipv4, ok := ipLayer.(*layers.IPv4); ok {
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
	} else if ipv6, ok := ipLayer.(*layers.IPv6); ok {
		srcIP = ipv6.SrcIP.String()
		dstIP = ipv6.DstIP.String()
	} else {
		return
	}

	connKey := srcIP + ":" + tcp.SrcPort.String() + ":" + dstIP + ":" + dstPort

	ma.connMu.Lock()
	defer ma.connMu.Unlock()

	normalizedPort := normalizePort(dstPort)
	delete(ma.tcpConnections, connKey)
	ma.collector.TCPConnectionsClosedTotal.WithLabelValues(ma.interface_, normalizedPort, reason).Inc()
	ma.updateActiveConnectionsGauge()
}

// updateActiveConnectionsGauge recalculates and updates active connections
func (ma *MetricsAggregator) updateActiveConnectionsGauge() {
	// Count active connections by state and port (normalized)
	stateCounts := make(map[string]int)

	for _, conn := range ma.tcpConnections {
		normalizedPort := normalizePort(conn.dstPort)
		key := conn.state + "|" + normalizedPort
		stateCounts[key]++
	}

	// Reset old gauges to 0 (cleanup stale label combinations)
	for prevKey := range ma.previousGaugeLabels {
		if _, exists := stateCounts[prevKey]; !exists {
			// This label combination no longer exists, set to 0
			state, port := ma.splitGaugeKey(prevKey)
			if state != "" && port != "" {
				ma.collector.TCPConnectionsActive.WithLabelValues(ma.interface_, state, port).Set(0)
			}
		}
	}

	// Update current gauges and track label combinations
	currentLabels := make(map[string]bool)
	for key, count := range stateCounts {
		state, port := ma.splitGaugeKey(key)
		if state != "" && port != "" {
			ma.collector.TCPConnectionsActive.WithLabelValues(ma.interface_, state, port).Set(float64(count))
			currentLabels[key] = true
		}
	}

	ma.previousGaugeLabels = currentLabels
}

// splitGaugeKey splits "state|port" into separate values
func (ma *MetricsAggregator) splitGaugeKey(key string) (state, port string) {
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			return key[:i], key[i+1:]
		}
	}
	return "", ""
}

// processUDP handles UDP metrics
func (ma *MetricsAggregator) processUDP(packet gopacket.Packet) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	udp := udpLayer.(*layers.UDP)
	dstPort := udp.DstPort.String()
	normalizedPort := normalizePort(dstPort) // Normalize for metrics label

	ma.collector.UDPPacketsTotal.WithLabelValues(ma.interface_, normalizedPort).Inc()
	ma.collector.PacketsTotal.WithLabelValues(ma.interface_, "udp").Inc()
	ma.collector.BytesTotal.WithLabelValues(ma.interface_, "udp").Add(float64(len(packet.Data())))
}

// processICMPv4 handles ICMPv4 metrics
func (ma *MetricsAggregator) processICMPv4(packet gopacket.Packet) {
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		return
	}

	icmp := icmpLayer.(*layers.ICMPv4)
	icmpType := ma.icmpTypeToString(uint8(icmp.TypeCode.Type()))

	ma.collector.ICMPPacketsTotal.WithLabelValues(ma.interface_, icmpType).Inc()
	ma.collector.PacketsTotal.WithLabelValues(ma.interface_, "icmp").Inc()
	ma.collector.BytesTotal.WithLabelValues(ma.interface_, "icmp").Add(float64(len(packet.Data())))
}

// processICMPv6 handles ICMPv6 metrics
func (ma *MetricsAggregator) processICMPv6(packet gopacket.Packet) {
	icmpLayer := packet.Layer(layers.LayerTypeICMPv6)
	if icmpLayer == nil {
		return
	}

	icmp := icmpLayer.(*layers.ICMPv6)
	icmpType := ma.icmpv6TypeToString(uint8(icmp.TypeCode.Type()))

	ma.collector.ICMPPacketsTotal.WithLabelValues(ma.interface_, icmpType).Inc()
	ma.collector.PacketsTotal.WithLabelValues(ma.interface_, "icmpv6").Inc()
	ma.collector.BytesTotal.WithLabelValues(ma.interface_, "icmpv6").Add(float64(len(packet.Data())))
}

// icmpTypeToString converts ICMP type to string
func (ma *MetricsAggregator) icmpTypeToString(t uint8) string {
	switch t {
	case 0:
		return "echo_reply"
	case 8:
		return "echo_request"
	case 3:
		return "dest_unreachable"
	case 11:
		return "time_exceeded"
	default:
		return "other"
	}
}

// icmpv6TypeToString converts ICMPv6 type to string
func (ma *MetricsAggregator) icmpv6TypeToString(t uint8) string {
	switch t {
	case 128:
		return "echo_request"
	case 129:
		return "echo_reply"
	case 1:
		return "dest_unreachable"
	default:
		return "other"
	}
}

// recordIPMetrics tracks unique IPs
func (ma *MetricsAggregator) recordIPMetrics(srcIP, dstIP string) {
	now := time.Now()

	ma.ipMu.Lock()
	ma.uniqueSrcIPs[srcIP] = now
	ma.uniqueDstIPs[dstIP] = now
	ma.ipMu.Unlock()

	// Update unique IP metrics
	ma.updateUniqueIPMetrics()
}

// updateUniqueIPMetrics updates the unique IP gauges
func (ma *MetricsAggregator) updateUniqueIPMetrics() {
	ma.ipMu.RLock()
	defer ma.ipMu.RUnlock()

	ma.collector.UniqueIPs.WithLabelValues(ma.interface_, "src", "1m").Set(float64(len(ma.uniqueSrcIPs)))
	ma.collector.UniqueIPs.WithLabelValues(ma.interface_, "dst", "1m").Set(float64(len(ma.uniqueDstIPs)))
}

// cleanupOldIPs removes IPs older than 1 minute
func (ma *MetricsAggregator) cleanupOldIPs(now time.Time) {
	ma.ipMu.Lock()
	defer ma.ipMu.Unlock()

	oneMinuteAgo := now.Add(-1 * time.Minute)

	for ip, lastSeen := range ma.uniqueSrcIPs {
		if lastSeen.Before(oneMinuteAgo) {
			delete(ma.uniqueSrcIPs, ip)
		}
	}

	for ip, lastSeen := range ma.uniqueDstIPs {
		if lastSeen.Before(oneMinuteAgo) {
			delete(ma.uniqueDstIPs, ip)
		}
	}

	ma.lastIPCleanup = now
}

// cleanupStaleConnections removes connections older than 2 minutes
// This catches half-open connections, lost FIN packets, and connections
// that were already established before packet capture started
func (ma *MetricsAggregator) cleanupStaleConnections(now time.Time) {
	ma.connMu.Lock()
	defer ma.connMu.Unlock()

	twoMinutesAgo := now.Add(-2 * time.Minute)

	for key, conn := range ma.tcpConnections {
		if conn.lastSeen.Before(twoMinutesAgo) {
			delete(ma.tcpConnections, key)
		}
	}

	// Update gauges after cleanup
	ma.updateActiveConnectionsGauge()
}

// Stop gracefully stops the metrics aggregator
func (ma *MetricsAggregator) Stop() {
	const op = "sniffer.MetricsAggregator.Stop"
	log := ma.log.With(slog.String("op", op))

	if !ma.running.Load() {
		return
	}

	log.Info("Stopping metrics aggregator")
	ma.running.Store(false)
	close(ma.stopChan)
	ma.wg.Wait()

	// Mark capture as inactive
	ma.collector.CaptureActive.WithLabelValues(ma.interface_).Set(0)

	log.Info("Metrics aggregator stopped")
}

// IsRunning returns whether the aggregator is running
func (ma *MetricsAggregator) IsRunning() bool {
	return ma.running.Load()
}
