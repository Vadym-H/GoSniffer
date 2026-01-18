package broadcaster

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/Vadym-H/GoSniffer/internal/sniffer/capture"
	"github.com/google/gopacket"
)

type PacketBroadcaster struct {
	source      *capture.PacketStream
	consumers   []chan gopacket.Packet
	mu          sync.RWMutex
	wg          sync.WaitGroup
	stopChan    chan struct{}
	log         *slog.Logger
	droppedPkts atomic.Int64
}

func NewPacketBroadcaster(source *capture.PacketStream, log *slog.Logger) *PacketBroadcaster {
	return &PacketBroadcaster{
		source:    source,
		consumers: make([]chan gopacket.Packet, 0),
		stopChan:  make(chan struct{}),
		log:       log.With(slog.String("component", "broadcaster")),
	}
}

// RegisterConsumer creates and returns a new channel for a consumer
func (b *PacketBroadcaster) RegisterConsumer(bufferSize int) chan gopacket.Packet {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan gopacket.Packet, bufferSize)
	b.consumers = append(b.consumers, ch)
	b.log.Info("Registered new consumer",
		slog.Int("consumerID", len(b.consumers)-1),
		slog.Int("bufferSize", bufferSize))

	return ch
}

// Start begins broadcasting packets to all registered consumers
func (b *PacketBroadcaster) Start() {
	b.wg.Add(1)
	go b.broadcastLoop()
}

func (b *PacketBroadcaster) broadcastLoop() {
	defer b.wg.Done()
	defer b.closeAllConsumers()

	b.log.Info("Broadcaster started", slog.Int("consumers", len(b.consumers)))

	for {
		select {
		case <-b.stopChan:
			b.log.Info("Broadcaster stopping")
			return

		case packet, ok := <-b.source.Packets:
			if !ok {
				b.log.Info("Source packet channel closed")
				return
			}
			b.broadcastPacket(packet)

		case err, ok := <-b.source.Errors:
			if !ok {
				return
			}
			b.log.Error("Capture error", slog.String("error", err.Error()))
		}
	}
}

func (b *PacketBroadcaster) broadcastPacket(packet gopacket.Packet) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Send to all consumers
	for i, consumer := range b.consumers {
		select {
		case consumer <- packet:
			// Successfully sent
		default:
			// Consumer channel is full - packet dropped for this consumer
			b.droppedPkts.Add(1)
			b.log.Warn("Consumer channel full, packet dropped",
				slog.Int("consumerID", i),
				slog.Int64("totalDropped", b.droppedPkts.Load()))
		}
	}
}

func (b *PacketBroadcaster) closeAllConsumers() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i, consumer := range b.consumers {
		close(consumer)
		b.log.Info("Closed consumer channel", slog.Int("consumerID", i))
	}
}

// Stop gracefully shuts down the broadcaster
func (b *PacketBroadcaster) Stop() {
	close(b.stopChan)
	b.wg.Wait()
	b.log.Info("Broadcaster stopped", slog.Int64("droppedPackets", b.droppedPkts.Load()))
}

// GetDroppedPacketCount returns the number of packets dropped due to full buffers
func (b *PacketBroadcaster) GetDroppedPacketCount() int64 {
	return b.droppedPkts.Load()
}
