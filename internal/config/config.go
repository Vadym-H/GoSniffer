package config

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Env                 string     `yaml:"env" env:"ENV" env-default:"local"`
	Interface           string     `yaml:"interface" env:"INTERFACE" env-default:"wlo1"`
	ProcessorWorkers    int        `yaml:"processor_workers" env:"PROCESSOR_WORKERS" env-default:"4"`
	EnableMetrics       bool       `yaml:"enable_metrics" env:"ENABLE_METRICS" env-default:"false"`
	EnableConsoleWriter bool       `yaml:"enable_console_writer" env:"ENABLE_CONSOLE_WRITER" env-default:"false"`
	Filters             BpfFilters `yaml:"filters"`
	HTTPServer          `yaml:"http_server"`
	PasswordHash        []byte
}
type HTTPServer struct {
	Address     string        `yaml:"address" env-default:":8080"`
	Timeout     time.Duration `yaml:"timeout" env-default:"4s"`
	IdleTimeout time.Duration `yaml:"idle_timeout" env-default:"120s"`
}
type BpfFilters struct {
	Protocols Protocols `yaml:"protocols" json:"protocols"`
	SrcIP     string    `yaml:"src_ip" json:"src_ip"`
	DstIP     string    `yaml:"dst_ip" json:"dst_ip"`
	Ports     string    `yaml:"ports" json:"ports"`
}

type Protocols struct {
	TCP  bool `yaml:"tcp" json:"tcp"`
	UDP  bool `yaml:"udp" json:"udp"`
	ICMP bool `yaml:"icmp" json:"icmp"`
	DNS  bool `yaml:"dns" json:"dns"`
}

func MustLoad() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Parse flags to allow overriding env vars with command-line arguments
	flag.Parse()

	// Get config path
	configPath := fetchConfigPath()
	if configPath == "" {
		log.Fatal("CONFIG_PATH is not set")
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Fatalf("Config file %s does not found", configPath)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		log.Fatalf("Failed to load config: %s", err)
	}

	// Get application password
	password := fetchAppPassword()
	if password == "" {
		log.Fatal("APP_PASSWORD is not set")
	}

	// Hash password, and store to config structure
	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}

	cfg.PasswordHash = hash
	return &cfg
}

func fetchConfigPath() string {
	res := os.Getenv("CONFIG_PATH")
	if res == "" {
		// try to get path from flag
		flag.StringVar(&res, "config", "", "Path to configuration file")
	}
	return res
}

func fetchAppPassword() string {
	res := os.Getenv("APP_PASSWORD")
	if res == "" {
		// try to get path from flag
		flag.StringVar(&res, "password", "", "Application password, one password for all users")
	}
	return res
}
