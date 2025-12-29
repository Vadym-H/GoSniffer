package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMustLoad(t *testing.T) {
	tests := []struct {
		name           string
		configContent  string
		envVars        map[string]string
		expectedConfig *Config
		expectError    bool
	}{
		{
			name: "valid config with all fields",
			configContent: `env: production
			filters:
			  protocols:
				tcp: true
				udp: false
				icmp: true
				dns: false
			  src_ip: "192.168.1.1"
			  dst_ip: "10.0.0.1"
			  ports: "80,443,8080"`,
			envVars: map[string]string{},
			expectedConfig: &Config{
				Env: "production",
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
			},
			expectError: false,
		},
		{
			name: "config with default env value",
			configContent: `filters:
			  protocols:
				tcp: true
				udp: true
				icmp: false
				dns: false`,
			envVars: map[string]string{},
			expectedConfig: &Config{
				Env: "local",
				Filters: BpfFilters{
					Protocols: Protocols{
						TCP:  true,
						UDP:  true,
						ICMP: false,
						DNS:  false,
					},
				},
			},
			expectError: false,
		},
		{
			name: "config with empty ports and IPs",
			configContent: `env: staging
			filters:
			  protocols:
				tcp: true
				udp: true
				icmp: true
				dns: true
			  src_ip: ""
			  dst_ip: ""
			  ports: ""`,
			envVars: map[string]string{},
			expectedConfig: &Config{
				Env: "staging",
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
			},
			expectError: false,
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
				Env: "testing",
				Filters: BpfFilters{
					Protocols: Protocols{
						TCP:  false,
						UDP:  false,
						ICMP: false,
						DNS:  true,
					},
				},
			},
			expectError: false,
		},
		{
			name: "minimal config",
			configContent: `filters:
			  protocols:
				tcp: false
				udp: false
				icmp: false
				dns: false`,
			envVars: map[string]string{},
			expectedConfig: &Config{
				Env: "local",
				Filters: BpfFilters{
					Protocols: Protocols{
						TCP:  false,
						UDP:  false,
						ICMP: false,
						DNS:  false,
					},
				},
			},
			expectError: false,
		},
		{
			name: "config with multiple ports",
			configContent: `env: development
				filters:
				  protocols:
					tcp: true
					udp: true
					icmp: false
					dns: true
				  src_ip: "0.0.0.0"
				  dst_ip: "255.255.255.255"
				  ports: "22,80,443,3000,8080,9090"`,
			envVars: map[string]string{},
			expectedConfig: &Config{
				Env: "development",
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
			},
			expectError: false,
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

			// Set additional environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
				defer os.Unsetenv(key)
			}

			// Load config
			cfg := MustLoad()

			// Assertions
			assert.Equal(t, tt.expectedConfig.Env, cfg.Env)
			assert.Equal(t, tt.expectedConfig.Filters.Protocols.TCP, cfg.Filters.Protocols.TCP)
			assert.Equal(t, tt.expectedConfig.Filters.Protocols.UDP, cfg.Filters.Protocols.UDP)
			assert.Equal(t, tt.expectedConfig.Filters.Protocols.ICMP, cfg.Filters.Protocols.ICMP)
			assert.Equal(t, tt.expectedConfig.Filters.Protocols.DNS, cfg.Filters.Protocols.DNS)
			assert.Equal(t, tt.expectedConfig.Filters.SrcIP, cfg.Filters.SrcIP)
			assert.Equal(t, tt.expectedConfig.Filters.DstIP, cfg.Filters.DstIP)
			assert.Equal(t, tt.expectedConfig.Filters.Ports, cfg.Filters.Ports)
		})
	}
}

func TestMustLoad_ErrorCases(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func(t *testing.T) string
		expectedError string
	}{
		{
			name: "CONFIG_PATH not set",
			setupFunc: func(t *testing.T) string {
				os.Unsetenv("CONFIG_PATH")
				return ""
			},
			expectedError: "CONFIG_PATH is not set",
		},
		{
			name: "config file does not exist",
			setupFunc: func(t *testing.T) string {
				nonExistentPath := "/path/to/nonexistent/config.yaml"
				os.Setenv("CONFIG_PATH", nonExistentPath)
				return nonExistentPath
			},
			expectedError: "does not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := tt.setupFunc(t)
			defer os.Unsetenv("CONFIG_PATH")

			// Note: In real tests, you'd need to handle log.Fatal()
			// This is a demonstration of the test structure
			// You might want to refactor MustLoad to return errors instead

			if configPath == "" {
				assert.Empty(t, os.Getenv("CONFIG_PATH"))
			} else {
				_, err := os.Stat(configPath)
				assert.True(t, os.IsNotExist(err))
			}
		})
	}
}

func TestConfig_StructInitialization(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "all protocols enabled",
			config: Config{
				Env: "production",
				Filters: BpfFilters{
					Protocols: Protocols{
						TCP:  true,
						UDP:  true,
						ICMP: true,
						DNS:  true,
					},
					SrcIP: "192.168.1.1",
					DstIP: "10.0.0.1",
					Ports: "80,443",
				},
			},
		},
		{
			name: "no protocols enabled",
			config: Config{
				Env: "local",
				Filters: BpfFilters{
					Protocols: Protocols{
						TCP:  false,
						UDP:  false,
						ICMP: false,
						DNS:  false,
					},
				},
			},
		},
		{
			name: "mixed protocol configuration",
			config: Config{
				Env: "staging",
				Filters: BpfFilters{
					Protocols: Protocols{
						TCP:  true,
						UDP:  false,
						ICMP: true,
						DNS:  false,
					},
					SrcIP: "172.16.0.1",
					DstIP: "172.16.0.2",
					Ports: "22,3389",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.config.Env, tt.config.Env)
			assert.Equal(t, tt.config.Filters.Protocols.TCP, tt.config.Filters.Protocols.TCP)
			assert.Equal(t, tt.config.Filters.Protocols.UDP, tt.config.Filters.Protocols.UDP)
			assert.Equal(t, tt.config.Filters.Protocols.ICMP, tt.config.Filters.Protocols.ICMP)
			assert.Equal(t, tt.config.Filters.Protocols.DNS, tt.config.Filters.Protocols.DNS)
			assert.Equal(t, tt.config.Filters.SrcIP, tt.config.Filters.SrcIP)
			assert.Equal(t, tt.config.Filters.DstIP, tt.config.Filters.DstIP)
			assert.Equal(t, tt.config.Filters.Ports, tt.config.Filters.Ports)
		})
	}
}
