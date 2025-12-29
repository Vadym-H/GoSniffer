package bpfFilter_test

import (
	"testing"

	"github.com/Vadym-H/GoSniffer/internal/config"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/BpfFilter"
)

func TestBuildBPFFilter(t *testing.T) {
	tests := []struct {
		name     string
		filters  config.BpfFilters
		expected string
	}{
		{
			name: "all filters enabled",
			filters: config.BpfFilters{
				Protocols: config.Protocols{
					TCP:  true,
					UDP:  true,
					ICMP: false,
					DNS:  false,
				},
				SrcIP: "192.168.1.100",
				DstIP: "10.0.0.1",
				Ports: "80,443",
			},
			expected: "(tcp or udp) and src host 192.168.1.100 and dst host 10.0.0.1 and (port 80 or port 443)",
		},
		{
			name: "single protocol and port",
			filters: config.BpfFilters{
				Protocols: config.Protocols{
					TCP:  true,
					UDP:  false,
					ICMP: false,
					DNS:  false,
				},
				SrcIP: "",
				DstIP: "",
				Ports: "443",
			},
			expected: "tcp and port 443",
		},
		{
			name: "only DNS protocol",
			filters: config.BpfFilters{
				Protocols: config.Protocols{
					TCP:  false,
					UDP:  false,
					ICMP: false,
					DNS:  true,
				},
				SrcIP: "",
				DstIP: "",
				Ports: "",
			},
			expected: "port 53",
		},
		{
			name: "all protocols",
			filters: config.BpfFilters{
				Protocols: config.Protocols{
					TCP:  true,
					UDP:  true,
					ICMP: true,
					DNS:  true,
				},
				SrcIP: "",
				DstIP: "",
				Ports: "",
			},
			expected: "(tcp or udp or icmp or port 53)",
		},
		{
			name: "only source IP",
			filters: config.BpfFilters{
				Protocols: config.Protocols{},
				SrcIP:     "192.168.1.1",
				DstIP:     "",
				Ports:     "",
			},
			expected: "src host 192.168.1.1",
		},
		{
			name: "only destination IP",
			filters: config.BpfFilters{
				Protocols: config.Protocols{},
				SrcIP:     "",
				DstIP:     "8.8.8.8",
				Ports:     "",
			},
			expected: "dst host 8.8.8.8",
		},
		{
			name: "both IPs",
			filters: config.BpfFilters{
				Protocols: config.Protocols{},
				SrcIP:     "192.168.1.1",
				DstIP:     "8.8.8.8",
				Ports:     "",
			},
			expected: "src host 192.168.1.1 and dst host 8.8.8.8",
		},
		{
			name: "multiple ports",
			filters: config.BpfFilters{
				Protocols: config.Protocols{},
				SrcIP:     "",
				DstIP:     "",
				Ports:     "22,80,443,8080",
			},
			expected: "(port 22 or port 80 or port 443 or port 8080)",
		},
		{
			name: "ports with spaces",
			filters: config.BpfFilters{
				Protocols: config.Protocols{},
				SrcIP:     "",
				DstIP:     "",
				Ports:     "80, 443, 8080",
			},
			expected: "(port 80 or port 443 or port 8080)",
		},
		{
			name: "empty filters (capture all)",
			filters: config.BpfFilters{
				Protocols: config.Protocols{},
				SrcIP:     "",
				DstIP:     "",
				Ports:     "",
			},
			expected: "",
		},
		{
			name: "complex real-world scenario",
			filters: config.BpfFilters{
				Protocols: config.Protocols{
					TCP:  true,
					UDP:  true,
					ICMP: false,
					DNS:  true,
				},
				SrcIP: "10.0.0.5",
				DstIP: "",
				Ports: "80,443,8080,3000",
			},
			expected: "(tcp or udp or port 53) and src host 10.0.0.5 and (port 80 or port 443 or port 8080 or port 3000)",
		},
		{
			name: "ICMP only",
			filters: config.BpfFilters{
				Protocols: config.Protocols{
					TCP:  false,
					UDP:  false,
					ICMP: true,
					DNS:  false,
				},
				SrcIP: "",
				DstIP: "",
				Ports: "",
			},
			expected: "icmp",
		},
		{
			name: "TCP and ICMP",
			filters: config.BpfFilters{
				Protocols: config.Protocols{
					TCP:  true,
					UDP:  false,
					ICMP: true,
					DNS:  false,
				},
				SrcIP: "",
				DstIP: "",
				Ports: "",
			},
			expected: "(tcp or icmp)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bpfFilter.BuildBPFFilter(&tt.filters)
			if result != tt.expected {
				t.Errorf("BuildBPFFilter() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestBuildProtocolFilter(t *testing.T) {
	tests := []struct {
		name      string
		protocols config.Protocols
		expected  string
	}{
		{
			name: "TCP only",
			protocols: config.Protocols{
				TCP:  true,
				UDP:  false,
				ICMP: false,
				DNS:  false,
			},
			expected: "tcp",
		},
		{
			name: "TCP and UDP",
			protocols: config.Protocols{
				TCP:  true,
				UDP:  true,
				ICMP: false,
				DNS:  false,
			},
			expected: "(tcp or udp)",
		},
		{
			name: "all protocols",
			protocols: config.Protocols{
				TCP:  true,
				UDP:  true,
				ICMP: true,
				DNS:  true,
			},
			expected: "(tcp or udp or icmp or port 53)",
		},
		{
			name: "DNS only",
			protocols: config.Protocols{
				TCP:  false,
				UDP:  false,
				ICMP: false,
				DNS:  true,
			},
			expected: "port 53",
		},
		{
			name: "no protocols",
			protocols: config.Protocols{
				TCP:  false,
				UDP:  false,
				ICMP: false,
				DNS:  false,
			},
			expected: "",
		},
		{
			name: "UDP and DNS",
			protocols: config.Protocols{
				TCP:  false,
				UDP:  true,
				ICMP: false,
				DNS:  true,
			},
			expected: "(udp or port 53)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filters := &config.BpfFilters{
				Protocols: tt.protocols,
			}
			result := bpfFilter.BuildProtocolFilter(filters)
			if result != tt.expected {
				t.Errorf("buildProtocolFilter() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestBuildPortFilter(t *testing.T) {
	tests := []struct {
		name     string
		ports    string
		expected string
	}{
		{
			name:     "single port",
			ports:    "80",
			expected: "port 80",
		},
		{
			name:     "multiple ports",
			ports:    "80,443,8080",
			expected: "(port 80 or port 443 or port 8080)",
		},
		{
			name:     "ports with spaces",
			ports:    "80, 443, 8080",
			expected: "(port 80 or port 443 or port 8080)",
		},
		{
			name:     "empty string",
			ports:    "",
			expected: "",
		},
		{
			name:     "port 1 (minimum valid)",
			ports:    "1",
			expected: "port 1",
		},
		{
			name:     "port 65535 (maximum valid)",
			ports:    "65535",
			expected: "port 65535",
		},
		{
			name:     "invalid port ignored (zero)",
			ports:    "0,80",
			expected: "port 80",
		},
		{
			name:     "invalid port ignored (too large)",
			ports:    "80,70000",
			expected: "port 80",
		},
		{
			name:     "invalid port ignored (negative)",
			ports:    "-1,443",
			expected: "port 443",
		},
		{
			name:     "invalid port ignored (non-numeric)",
			ports:    "abc,443",
			expected: "port 443",
		},
		{
			name:     "all invalid ports",
			ports:    "0,70000,abc",
			expected: "",
		},
		{
			name:     "mixed valid and invalid",
			ports:    "80,invalid,443,99999,22",
			expected: "(port 80 or port 443 or port 22)",
		},
		{
			name:     "common web ports",
			ports:    "80,443,8080,8443",
			expected: "(port 80 or port 443 or port 8080 or port 8443)",
		},
		{
			name:     "trailing comma",
			ports:    "80,443,",
			expected: "(port 80 or port 443)",
		},
		{
			name:     "leading comma",
			ports:    ",80,443",
			expected: "(port 80 or port 443)",
		},
		{
			name:     "extra spaces everywhere",
			ports:    "  80  ,  443  ,  8080  ",
			expected: "(port 80 or port 443 or port 8080)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filters := &config.BpfFilters{
				Ports: tt.ports,
			}
			result := bpfFilter.BuildPortFilter(filters)
			if result != tt.expected {
				t.Errorf("buildPortFilter() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// Benchmark tests
func BenchmarkBuildBPFFilter(b *testing.B) {
	filters := &config.BpfFilters{
		Protocols: config.Protocols{
			TCP:  true,
			UDP:  true,
			ICMP: false,
			DNS:  true,
		},
		SrcIP: "192.168.1.100",
		DstIP: "10.0.0.1",
		Ports: "80,443,8080,3000,5000",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bpfFilter.BuildBPFFilter(filters)
	}
}

func BenchmarkBuildPortFilter(b *testing.B) {
	filters := &config.BpfFilters{
		Ports: "80,443,8080,3000,5000,8443,9090,3306,5432,6379",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bpfFilter.BuildPortFilter(filters)
	}
}
