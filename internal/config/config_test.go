package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMustLoad(t *testing.T) {
	tests := []struct {
		name           string
		configContent  string
		envVars        map[string]string
		expectedConfig *Config
	}{
		{
			name: "valid config with all fields",
			configContent: `env: production
processor_workers: 8
filters:
  protocols:
    tcp: true
    udp: false
    icmp: true
    dns: false
  src_ip: "192.168.1.1"
  dst_ip: "10.0.0.1"
  ports: "80,443,8080"
http_server:
  address: ":9090"
  timeout: 5s
  idle_timeout: 60s`,
			envVars: map[string]string{},
			expectedConfig: &Config{
				Env:              "production",
				ProcessorWorkers: 8,
				Filters: BpfFilters{
					Protocols: Protocols{
						TCP:  true,
						UDP:  false,
						ICMP: true,
						DNS:  false,
					},
					SrcIP: "192.168.1.1",
					DstIP: "10.0.0.1",
					Ports: "80,443,8080",
				},
				HTTPServer: HTTPServer{
					Address:     ":9090",
					Timeout:     5 * time.Second,
					IdleTimeout: 60 * time.Second,
				},
			},
		},
		{
			name: "config with default env and processor workers",
			configContent: `filters:
  protocols:
    tcp: true
    udp: true
    icmp: false
    dns: false`,
			envVars: map[string]string{},
			expectedConfig: &Config{
				Env:              "local",
				ProcessorWorkers: 4,
				Filters: BpfFilters{
					Protocols: Protocols{
						TCP:  true,
						UDP:  true,
						ICMP: false,
						DNS:  false,
					},
				},
				HTTPServer: HTTPServer{
					Address:     ":8080",
					Timeout:     4 * time.Second,
					IdleTimeout: 120 * time.Second,
				},
			},
		},
		{
			name: "config with empty ports and IPs",
			configContent: `env: staging
processor_workers: 2
filters:
  protocols:
    tcp: true
    udp: true
    icmp: true
    dns: true
  src_ip: ""
  dst_ip: ""
  ports: ""
http_server:
  address: ":3000"`,
			envVars: map[string]string{},
			expectedConfig: &Config{
				Env:              "staging",
				ProcessorWorkers: 2,
				Filters: BpfFilters{
					Protocols: Protocols{
						TCP:  true,
						UDP:  true,
						ICMP: true,
						DNS:  true,
					},
					SrcIP: "",
					DstIP: "",
					Ports: "",
				},
				HTTPServer: HTTPServer{
					Address:     ":3000",
					Timeout:     4 * time.Second,
					IdleTimeout: 120 * time.Second,
				},
			},
		},
		{
			name: "config with env override from environment variable",
			configContent: `filters:
  protocols:
    tcp: false
    udp: false
    icmp: false
    dns: true`,
			envVars: map[string]string{
				"ENV": "testing",
			},
			expectedConfig: &Config{
				Env:              "testing",
				ProcessorWorkers: 4,
				Filters: BpfFilters{
					Protocols: Protocols{
						TCP:  false,
						UDP:  false,
						ICMP: false,
						DNS:  true,
					},
				},
				HTTPServer: HTTPServer{
					Address:     ":8080",
					Timeout:     4 * time.Second,
					IdleTimeout: 120 * time.Second,
				},
			},
		},
		{
			name: "config with multiple ports and filters",
			configContent: `env: development
processor_workers: 6
filters:
  protocols:
    tcp: true
    udp: true
    icmp: false
    dns: true
  src_ip: "0.0.0.0"
  dst_ip: "255.255.255.255"
  ports: "22,80,443,3000,8080,9090"
http_server:
  address: ":8000"
  timeout: 10s
  idle_timeout: 180s`,
			envVars: map[string]string{},
			expectedConfig: &Config{
				Env:              "development",
				ProcessorWorkers: 6,
				Filters: BpfFilters{
					Protocols: Protocols{
						TCP:  true,
						UDP:  true,
						ICMP: false,
						DNS:  true,
					},
					SrcIP: "0.0.0.0",
					DstIP: "255.255.255.255",
					Ports: "22,80,443,3000,8080,9090",
				},
				HTTPServer: HTTPServer{
					Address:     ":8000",
					Timeout:     10 * time.Second,
					IdleTimeout: 180 * time.Second,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory and config file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")

			err := os.WriteFile(configPath, []byte(tt.configContent), 0644)
			require.NoError(t, err)

			// Set CONFIG_PATH environment variable
			os.Setenv("CONFIG_PATH", configPath)
			defer os.Unsetenv("CONFIG_PATH")

			// Set APP_PASSWORD for password hashing
			os.Setenv("APP_PASSWORD", "testpassword123")
			defer os.Unsetenv("APP_PASSWORD")

			// Set additional environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
				defer os.Unsetenv(key)
			}

			// Load config
			cfg := MustLoad()

			// Assertions for basic fields
			assert.Equal(t, tt.expectedConfig.Env, cfg.Env)
			assert.Equal(t, tt.expectedConfig.ProcessorWorkers, cfg.ProcessorWorkers)

			// Assertions for filters
			assert.Equal(t, tt.expectedConfig.Filters.Protocols.TCP, cfg.Filters.Protocols.TCP)
			assert.Equal(t, tt.expectedConfig.Filters.Protocols.UDP, cfg.Filters.Protocols.UDP)
			assert.Equal(t, tt.expectedConfig.Filters.Protocols.ICMP, cfg.Filters.Protocols.ICMP)
			assert.Equal(t, tt.expectedConfig.Filters.Protocols.DNS, cfg.Filters.Protocols.DNS)
			assert.Equal(t, tt.expectedConfig.Filters.SrcIP, cfg.Filters.SrcIP)
			assert.Equal(t, tt.expectedConfig.Filters.DstIP, cfg.Filters.DstIP)
			assert.Equal(t, tt.expectedConfig.Filters.Ports, cfg.Filters.Ports)

			// Assertions for HTTP server
			assert.Equal(t, tt.expectedConfig.HTTPServer.Address, cfg.HTTPServer.Address)
			assert.Equal(t, tt.expectedConfig.HTTPServer.Timeout, cfg.HTTPServer.Timeout)
			assert.Equal(t, tt.expectedConfig.HTTPServer.IdleTimeout, cfg.HTTPServer.IdleTimeout)

			// Assert password hash is set
			assert.NotNil(t, cfg.PasswordHash)
			assert.True(t, len(cfg.PasswordHash) > 0)
		})
	}
}
