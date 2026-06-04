package processor

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/Vadym-H/GoSniffer/internal/sniffer/capture"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output"
	"github.com/google/gopacket"
)

const batchSize = 100

type PacketProcessor struct {
	numWorkers  int
	log         *slog.Logger
	wg          sync.WaitGroup
	stopChan    chan struct{}
	packetCount atomic.Int64
	writer      output.PacketWriter
	packetChan  chan gopacket.Packet
	stream      *capture.PacketStream
}

func NewPacketProcessor(numWorkers int, writer output.PacketWriter, log *slog.Logger) *PacketProcessor {
	const op = "sniffer.processor.NewPacketProcessor"

	if !writer.SupportsConcurrentWrites() {
		log.Info("Writer requires sequential processing, using 1 worker")
		numWorkers = 1
	}

	return &PacketProcessor{
		numWorkers: numWorkers,
		log:        log.With(slog.String("op", op)),
		stopChan:   make(chan struct{}),
		writer:     writer,
	}
}

func (p *PacketProcessor) Start(packetChan chan gopacket.Packet, stream *capture.PacketStream) {
	const op = "sniffer.processor.Start"
	log := p.log.With(slog.String("op", op))

	p.packetChan = packetChan
	p.stream = stream
	log.Info("Starting packet processor", slog.Int("workers", p.numWorkers))

	// Start error handler goroutine
	p.wg.Add(1)
	go p.handleErrors(stream)

	// Spawn worker goroutines
	for i := 0; i < p.numWorkers; i++ {
		p.wg.Add(1)
		go p.worker(i, packetChan)
	}
}

func (p *PacketProcessor) worker(id int, packets <-chan gopacket.Packet) {
	const op = "sniffer.processor.worker"
	log := p.log.With(
		slog.String("op", op),
		slog.Int("workerID", id),
	)

	defer p.wg.Done()

	log.Info("Worker started")

	batch := make([]gopacket.Packet, 0, batchSize)

	for {
		batch = batch[:0]

		// Block until the first packet arrives or stop is signalled.
		select {
		case <-p.stopChan:
			log.Info("Worker stopping")
			return
		case pkt, ok := <-packets:
			if !ok {
				log.Info("Packet channel closed, worker stopping")
				return
			}
			batch = append(batch, pkt)
		}

		// Non-blocking drain: collect up to batchSize-1 more packets that are
		// already queued, so we write them under a single lock acquisition.
	drain:
		for len(batch) < batchSize {
			select {
			case pkt, ok := <-packets:
				if !ok {
					break drain
				}
				batch = append(batch, pkt)
			default:
				break drain
			}
		}

		// Atomically reserve a contiguous range of packet numbers for this batch.
		end := p.packetCount.Add(int64(len(batch)))
		startCount := int(end) - len(batch) + 1
		p.writer.WriteBatch(batch, startCount)
	}
}

func (p *PacketProcessor) handleErrors(stream *capture.PacketStream) {
	const op = "sniffer.processor.handleErrors"
	log := p.log.With(slog.String("op", op))

	defer p.wg.Done()

	for {
		select {
		case <-p.stopChan:
			return
		case err, ok := <-stream.Errors:
			if !ok {
				return
			}
			log.Error("Capture error", slog.String("error", err.Error()))
		}
	}
}

func (p *PacketProcessor) Stop() {
	const op = "sniffer.processor.Stop"
	log := p.log.With(slog.String("op", op))

	log.Info("Stopping packet processor")
	close(p.stopChan)
	p.wg.Wait()

	// ADD THESE LINES:
	if err := p.writer.Close(); err != nil {
		log.Error("Error closing writer", slog.String("error", err.Error()))
	}

	totalPackets := p.packetCount.Load()
	log.Info("Packet processor stopped", slog.Int64("totalPackets", totalPackets))
}

func (p *PacketProcessor) GetPacketCount() int64 {
	return p.packetCount.Load()
}
