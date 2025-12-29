package config

import (
	"log"
	"os"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
)

type Config struct {
	Env              string     `yaml:"env" env:"ENV" env-default:"local"`
	ProcessorWorkers int        `yaml:"processor_workers" env:"PROCESSOR_WORKERS" env-default:"4"`
	Filters          BpfFilters `yaml:"filters"`
}
type BpfFilters struct {
	Protocols Protocols `yaml:"protocols"`
	SrcIP     string    `yaml:"src_ip"`
	DstIP     string    `yaml:"dst_ip"`
	Ports     string    `yaml:"ports"` // "80,443,8080" or empty
}

type Protocols struct {
	TCP  bool `yaml:"tcp"`
	UDP  bool `yaml:"udp"`
	ICMP bool `yaml:"icmp"`
	DNS  bool `yaml:"dns"`
}

func MustLoad() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	configPath := os.Getenv("CONFIG_PATH")
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
	return &cfg
}
