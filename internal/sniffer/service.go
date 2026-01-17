package sniffer

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/Vadym-H/GoSniffer/internal/sniffer/capture"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/processor"
)

type Service struct {
	mu      sync.Mutex
	running bool

	device string

	stream *capture.PacketStream
	proc   *processor.PacketProcessor
	log    *slog.Logger
}

func New(log *slog.Logger) *Service {
	return &Service{log: log}
}

func (s *Service) SetDevice(device string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("cannot change device while running")
	}

	s.device = device
	return nil
}
