package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// MetricsCollector holds all Prometheus metrics
type MetricsCollector struct {
	mu sync.RWMutex

	// Basic Packet Counters
	PacketsTotal *prometheus.CounterVec
	BytesTotal   *prometheus.CounterVec

	// Dropped Packets
	PacketsDroppedTotal *prometheus.CounterVec

	// TCP Metrics
	TCPFlagsTotal             *prometheus.CounterVec
	TCPResetsTotal            *prometheus.CounterVec
	TCPConnectionsActive      *prometheus.GaugeVec
	TCPConnectionsOpenedTotal *prometheus.CounterVec
	TCPConnectionsClosedTotal *prometheus.CounterVec

	// UDP/ICMP Metrics
	UDPPacketsTotal  *prometheus.CounterVec
	ICMPPacketsTotal *prometheus.CounterVec

	// Server Health
	BandwidthBytesPerSecond *prometheus.GaugeVec
	UniqueIPs               *prometheus.GaugeVec

	// Capture Status
	CaptureActive *prometheus.GaugeVec
}

// NewMetricsCollector creates and registers all Prometheus metrics
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		// Basic Packet Counters
		PacketsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gosniffer",
				Name:      "packets_total",
				Help:      "Total packets captured by protocol",
			},
			[]string{"interface", "protocol"},
		),
		BytesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gosniffer",
				Name:      "bytes_total",
				Help:      "Total bytes captured by protocol",
			},
			[]string{"interface", "protocol"},
		),

		// Dropped Packets
		PacketsDroppedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gosniffer",
				Name:      "packets_dropped_total",
				Help:      "Total dropped packets by reason",
			},
			[]string{"interface", "reason"},
		),

		// TCP Metrics
		TCPFlagsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gosniffer",
				Name:      "tcp_flags_total",
				Help:      "TCP packets by flag and destination port",
			},
			[]string{"interface", "flag", "dst_port"},
		),
		TCPResetsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gosniffer",
				Name:      "tcp_resets_total",
				Help:      "TCP RST packets by destination port",
			},
			[]string{"interface", "dst_port"},
		),
		TCPConnectionsActive: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "gosniffer",
				Name:      "tcp_connections_active",
				Help:      "Active TCP connections by state and destination port",
			},
			[]string{"interface", "state", "dst_port"},
		),
		TCPConnectionsOpenedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gosniffer",
				Name:      "tcp_connections_opened_total",
				Help:      "Total TCP connections opened by destination port",
			},
			[]string{"interface", "dst_port"},
		),
		TCPConnectionsClosedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gosniffer",
				Name:      "tcp_connections_closed_total",
				Help:      "Total TCP connections closed by reason",
			},
			[]string{"interface", "dst_port", "reason"},
		),

		// UDP/ICMP Metrics
		UDPPacketsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gosniffer",
				Name:      "udp_packets_total",
				Help:      "UDP packets by destination port",
			},
			[]string{"interface", "dst_port"},
		),
		ICMPPacketsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "gosniffer",
				Name:      "icmp_packets_total",
				Help:      "ICMP packets by type",
			},
			[]string{"interface", "type"},
		),

		// Server Health
		BandwidthBytesPerSecond: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "gosniffer",
				Name:      "bandwidth_bytes_per_second",
				Help:      "Current bandwidth in bytes per second",
			},
			[]string{"interface", "direction"},
		),
		UniqueIPs: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "gosniffer",
				Name:      "unique_ips",
				Help:      "Unique IP addresses in sliding window",
			},
			[]string{"interface", "direction", "window"},
		),

		// Capture Status
		CaptureActive: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "gosniffer",
				Name:      "capture_active",
				Help:      "1 if capturing on interface, 0 if stopped",
			},
			[]string{"interface"},
		),
	}
}

// RecordPacket updates metrics for a packet
// This is called by the metrics aggregator
// For now, just a placeholder for the aggregator to call into
