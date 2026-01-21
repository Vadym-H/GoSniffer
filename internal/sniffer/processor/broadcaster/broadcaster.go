package broadcaster

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"time"

	"github.com/Vadym-H/GoSniffer/internal/sniffer/capture"
	"github.com/google/gopacket"
)

// ErrorRecord represents an error event with timestamp
type ErrorRecord struct {
	Timestamp int64
	Message   string
	ErrorType string // "capture", "processing"
}

type PacketBroadcaster struct {
	source      *capture.PacketStream
	consumers   []chan gopacket.Packet
	mu          sync.RWMutex
	wg          sync.WaitGroup
	stopChan    chan struct{}
	log         *slog.Logger
	droppedPkts atomic.Int64
	packetCount atomic.Int64 // Track total packets processed
	totalBytes  atomic.Int64 // Track total bytes processed

	// Error tracking
	errorMu          sync.RWMutex
	totalErrors      int64
	captureErrors    int64
	processingErrors int64
	lastErrorTime    int64
	lastErrorMessage string
	recentErrors     []ErrorRecord // Last N errors for last-minute tracking
}

func NewPacketBroadcaster(source *capture.PacketStream, log *slog.Logger) *PacketBroadcaster {
	return &PacketBroadcaster{
		source:       source,
		consumers:    make([]chan gopacket.Packet, 0),
		stopChan:     make(chan struct{}),
		log:          log.With(slog.String("component", "broadcaster")),
		recentErrors: make([]ErrorRecord, 0, 100), // Keep last 100 errors
	}
}

// RegisterConsumer creates and returns a new channel for a consumer
// Returns the consumer ID for later unregistration
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

// UnregisterConsumer removes a consumer by ID and closes its channel
func (b *PacketBroadcaster) UnregisterConsumer(consumerID int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if consumerID >= 0 && consumerID < len(b.consumers) {
		if b.consumers[consumerID] != nil {
			close(b.consumers[consumerID])
			b.consumers[consumerID] = nil // Mark as removed
			b.log.Info("Consumer unregistered", slog.Int("consumerID", consumerID))
		}
	}
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
	// Increment packet counter and track bytes
	b.packetCount.Add(1)
	b.totalBytes.Add(int64(packet.Metadata().Length))

	b.mu.RLock()
	defer b.mu.RUnlock()

	// Send to all consumers
	for i, consumer := range b.consumers {
		// Skip nil consumers (unregistered)
		if consumer == nil {
			continue
		}

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
		// Check if consumer is not nil before closing (may have been unregistered)
		if consumer != nil {
			close(consumer)
			b.log.Info("Closed consumer channel", slog.Int("consumerID", i))
		}
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

// GetStream returns the underlying packet stream source
func (b *PacketBroadcaster) GetStream() *capture.PacketStream {
	return b.source
}

// UnregisterAllRecordingConsumers unregisters all current consumers (used for recording cleanup)
func (b *PacketBroadcaster) UnregisterAllRecordingConsumers() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i, consumer := range b.consumers {
		if consumer != nil {
			close(consumer)
			b.consumers[i] = nil
			b.log.Info("Unregistered recording consumer", slog.Int("consumerID", i))
		}
	}
}

// GetConsumers returns the list of consumer channels (for consumer ID tracking)
func (b *PacketBroadcaster) GetConsumers() []chan gopacket.Packet {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.consumers
}

// GetPacketCount returns the total number of packets processed
func (b *PacketBroadcaster) GetPacketCount() int64 {
	return b.packetCount.Load()
}

// IncrementPacketCount increments the packet counter
func (b *PacketBroadcaster) IncrementPacketCount() {
	b.packetCount.Add(1)
}

// GetTotalBytes returns the total number of bytes processed
func (b *PacketBroadcaster) GetTotalBytes() int64 {
	return b.totalBytes.Load()
}

// GetSubscriberCount returns the number of active subscribers
func (b *PacketBroadcaster) GetSubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	count := 0
	for _, consumer := range b.consumers {
		if consumer != nil {
			count++
		}
	}
	return count
}

// RecordError records an error for tracking and metrics
func (b *PacketBroadcaster) RecordError(errorType string, message string) {
	b.errorMu.Lock()
	defer b.errorMu.Unlock()

	now := time.Now().Unix()
	b.totalErrors++
	b.lastErrorTime = now
	b.lastErrorMessage = message

	if errorType == "capture" {
		b.captureErrors++
	} else if errorType == "processing" {
		b.processingErrors++
	}

	// Add to recent errors (keep last 100)
	if len(b.recentErrors) >= 100 {
		b.recentErrors = b.recentErrors[1:]
	}
	b.recentErrors = append(b.recentErrors, ErrorRecord{
		Timestamp: now,
		Message:   message,
		ErrorType: errorType,
	})
}

// GetErrorMetrics returns current error metrics
func (b *PacketBroadcaster) GetErrorMetrics() (totalErrors, captureErrors, processingErrors int64, lastErrorTime int64, lastErrorMsg string, errorsLastMinute int) {
	b.errorMu.RLock()
	defer b.errorMu.RUnlock()

	totalErrors = b.totalErrors
	captureErrors = b.captureErrors
	processingErrors = b.processingErrors
	lastErrorTime = b.lastErrorTime
	lastErrorMsg = b.lastErrorMessage

	// Count errors in last minute
	now := time.Now().Unix()
	oneMinuteAgo := now - 60
	for _, err := range b.recentErrors {
		if err.Timestamp > oneMinuteAgo {
			errorsLastMinute++
		}
	}

	return
}
