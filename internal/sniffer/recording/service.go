package recording

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Vadym-H/GoSniffer/internal/config"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/filemanager"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/toFife/csvwriter"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/toFife/jsonwriter"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/output/toFife/pcapwriter"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/processor"
	"github.com/Vadym-H/GoSniffer/internal/sniffer/processor/broadcaster"
)

// RecordingFormat represents supported recording formats
type RecordingFormat string

const (
	FormatPCAP RecordingFormat = "pcap"
	FormatCSV  RecordingFormat = "csv"
	FormatJSON RecordingFormat = "json"
)

// RecordingStatus represents the current state of recording
type RecordingStatus string

const (
	StatusStopped   RecordingStatus = "stopped"
	StatusRecording RecordingStatus = "recording"
)

// RecordingInfo holds information about an active or completed recording
type RecordingInfo struct {
	Status           RecordingStatus `json:"status"`
	IsRecording      bool            `json:"is_recording"`
	StartTime        time.Time       `json:"start_time,omitempty"`
	EndTime          time.Time       `json:"end_time,omitempty"`
	DurationSeconds  int             `json:"duration_seconds,omitempty"`
	ElapsedSeconds   int             `json:"elapsed_seconds,omitempty"`
	RemainingSeconds int             `json:"remaining_seconds,omitempty"`
}

// SessionState holds the state of a single format recording session
type SessionState struct {
	isRecording bool
	startTime   time.Time
	duration    time.Duration
	cancelCtx   context.CancelFunc
	processor   *processor.PacketProcessor
	consumerID  int
}

// RecordingService manages independent recording sessions for each format
type RecordingService struct {
	mu               sync.RWMutex
	wg               sync.WaitGroup
	sessions         map[RecordingFormat]*SessionState
	broadcasterRef   *broadcaster.PacketBroadcaster
	interfaceRef     string
	cfg              *config.Config
	log              *slog.Logger
	fm               *filemanager.FileManager
	processorWorkers int
}

// NewRecordingService creates a new recording service
func NewRecordingService(cfg *config.Config, log *slog.Logger, fm *filemanager.FileManager) *RecordingService {
	return &RecordingService{
		sessions:         make(map[RecordingFormat]*SessionState),
		cfg:              cfg,
		log:              log,
		fm:               fm,
		processorWorkers: cfg.ProcessorWorkers,
	}
}

// SetBroadcasterRef sets the reference to the packet broadcaster
func (rs *RecordingService) SetBroadcasterRef(b *broadcaster.PacketBroadcaster, interfaceName string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.broadcasterRef = b
	rs.interfaceRef = interfaceName
}

// StartRecording begins a recording session for a specific format
func (rs *RecordingService) StartRecording(format RecordingFormat, durationSeconds int) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.broadcasterRef == nil {
		return fmt.Errorf("broadcaster not initialized")
	}

	if durationSeconds < 1 || durationSeconds > 3600 {
		return fmt.Errorf("duration must be between 1 and 3600 seconds")
	}

	session, exists := rs.sessions[format]
	if exists && session.isRecording {
		return fmt.Errorf("%s recording already in progress", format)
	}

	duration := time.Duration(durationSeconds) * time.Second
	ctx, cancel := context.WithCancel(context.Background())

	session = &SessionState{
		isRecording: true,
		startTime:   time.Now(),
		duration:    duration,
		cancelCtx:   cancel,
	}

	rs.sessions[format] = session

	// Start the recording session in a separate goroutine
	rs.wg.Add(1)
	go rs.runRecordingSession(ctx, duration, format, session)

	rs.log.Info("Recording started", slog.String("format", string(format)), slog.Int("duration_seconds", durationSeconds))
	return nil
}

// runRecordingSession runs the recording with automatic cleanup
func (rs *RecordingService) runRecordingSession(ctx context.Context, duration time.Duration, format RecordingFormat, session *SessionState) {
	defer rs.wg.Done()
	defer func() {
		rs.mu.Lock()
		session.isRecording = false
		rs.mu.Unlock()
		rs.log.Info("Recording session ended", slog.String("format", string(format)))
	}()

	var writer interface {
		Close() error
	}

	// Create the appropriate writer based on format
	switch format {
	case FormatPCAP:
		w, err := pcapwriter.NewPcapWriter(rs.interfaceRef, duration, rs.log, rs.fm)
		if err != nil {
			rs.log.Error("Failed to create PCAP writer", slog.String("error", err.Error()))
			return
		}
		writer = w
		session.processor = processor.NewPacketProcessor(rs.processorWorkers, w, rs.log)

	case FormatCSV:
		w, err := csvwriter.NewCSVWriter(rs.interfaceRef, duration, rs.log, rs.fm)
		if err != nil {
			rs.log.Error("Failed to create CSV writer", slog.String("error", err.Error()))
			return
		}
		writer = w
		session.processor = processor.NewPacketProcessor(rs.processorWorkers, w, rs.log)

	case FormatJSON:
		w, err := jsonwriter.NewJSONWriter(rs.interfaceRef, duration, rs.log, rs.fm)
		if err != nil {
			rs.log.Error("Failed to create JSON writer", slog.String("error", err.Error()))
			return
		}
		writer = w
		session.processor = processor.NewPacketProcessor(rs.processorWorkers, w, rs.log)

	default:
		rs.log.Error("Unknown format", slog.String("format", string(format)))
		return
	}

	// Register consumer
	ch := rs.broadcasterRef.RegisterConsumer(10000)
	session.consumerID = len(rs.broadcasterRef.GetConsumers()) - 1

	// Start processor
	session.processor.Start(ch, rs.broadcasterRef.GetStream())

	rs.log.Info("Recording processor started", slog.String("format", string(format)))

	// Wait for duration or context cancellation
	select {
	case <-time.After(duration):
		rs.log.Info("Recording duration expired", slog.String("format", string(format)))
	case <-ctx.Done():
		rs.log.Info("Recording stopped by user", slog.String("format", string(format)))
	}

	// Stop processor and cleanup
	session.processor.Stop()
	rs.broadcasterRef.UnregisterConsumer(session.consumerID)

	if writer != nil {
		writer.Close()
	}

	rs.log.Info("Recording writer stopped", slog.String("format", string(format)))
}

// StopRecording stops the recording session for a specific format
func (rs *RecordingService) StopRecording(format RecordingFormat) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	session, exists := rs.sessions[format]
	if !exists || !session.isRecording {
		return fmt.Errorf("no %s recording in progress", format)
	}

	if session.cancelCtx != nil {
		session.cancelCtx()
	}

	return nil
}

// StopAll cancels all active recording sessions and waits for them to flush and close their files.
func (rs *RecordingService) StopAll() {
	rs.mu.Lock()
	for _, session := range rs.sessions {
		if session.isRecording && session.cancelCtx != nil {
			session.cancelCtx()
		}
	}
	rs.mu.Unlock()
	rs.wg.Wait()
}

// GetStatus returns the current recording status for a specific format
func (rs *RecordingService) GetStatus(format RecordingFormat) RecordingInfo {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	session, exists := rs.sessions[format]
	if !exists {
		return RecordingInfo{Status: StatusStopped, IsRecording: false}
	}

	info := RecordingInfo{
		IsRecording: session.isRecording,
	}

	if session.isRecording {
		info.Status = StatusRecording
		info.StartTime = session.startTime
		info.DurationSeconds = int(session.duration.Seconds())
		elapsed := time.Since(session.startTime)
		info.ElapsedSeconds = int(elapsed.Seconds())
		remaining := session.duration - elapsed
		if remaining > 0 {
			info.RemainingSeconds = int(remaining.Seconds())
		} else {
			info.RemainingSeconds = 0
		}
	} else {
		info.Status = StatusStopped
	}

	return info
}
