package filemanager

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	baseDir              = "captures"
	maxFilesPerDirectory = 5
	pcapDir              = "pcap"
	csvDir               = "csv"
	jsonDir              = "json"
)

// FileManager handles file creation, naming, and automatic cleanup
type FileManager struct {
	baseDir string
	mu      sync.Mutex
	log     *slog.Logger
}

// NewFileManager creates a new file manager and initializes directories
func NewFileManager(log *slog.Logger) (*FileManager, error) {
	fm := &FileManager{
		baseDir: baseDir,
		log:     log,
	}

	// Create base directory if it doesn't exist
	if err := os.MkdirAll(fm.baseDir, 0755); err != nil {
		fm.log.Error("Failed to create base directory",
			slog.String("path", fm.baseDir),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	// Create subdirectories
	subdirs := []string{pcapDir, csvDir, jsonDir}
	for _, subdir := range subdirs {
		dirPath := filepath.Join(fm.baseDir, subdir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			fm.log.Error("Failed to create subdirectory",
				slog.String("path", dirPath),
				slog.String("error", err.Error()))
			return nil, fmt.Errorf("failed to create subdirectory %s: %w", dirPath, err)
		}
		fm.log.Debug("Subdirectory created or already exists", slog.String("path", dirPath))
	}

	fm.log.Info("FileManager initialized successfully", slog.String("base_dir", fm.baseDir))
	return fm, nil
}

// GetFilePath generates a timestamped file path and handles cleanup if max files reached
func (fm *FileManager) GetFilePath(fileType string) (string, error) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// Validate file type
	var subdir string
	var ext string
	switch fileType {
	case "pcap":
		subdir = pcapDir
		ext = "pcap"
	case "csv":
		subdir = csvDir
		ext = "csv"
	case "json":
		subdir = jsonDir
		ext = "json"
	default:
		return "", fmt.Errorf("invalid file type: %s", fileType)
	}

	dirPath := filepath.Join(fm.baseDir, subdir)

	// Check if directory exists and create if needed
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		fm.log.Error("Failed to ensure directory exists",
			slog.String("type", fileType),
			slog.String("path", dirPath),
			slog.String("error", err.Error()))
		return "", fmt.Errorf("failed to ensure directory: %w", err)
	}

	// Check and cleanup if max files reached
	if err := fm.cleanupOldestFileIfNeeded(dirPath, fileType); err != nil {
		fm.log.Warn("Error during cleanup check (non-fatal)",
			slog.String("type", fileType),
			slog.String("error", err.Error()))
		// Continue anyway, don't fail the operation
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("capture_%s.%s", timestamp, ext)
	filePath := filepath.Join(dirPath, filename)

	fm.log.Info("File path generated",
		slog.String("type", fileType),
		slog.String("path", filePath),
		slog.String("filename", filename))

	return filePath, nil
}

// cleanupOldestFileIfNeeded checks if the max file limit is reached and deletes the oldest file
func (fm *FileManager) cleanupOldestFileIfNeeded(dirPath, fileType string) error {
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	fileCount := len(files)

	// Log current file count
	fm.log.Debug("Checking file count in directory",
		slog.String("type", fileType),
		slog.String("path", dirPath),
		slog.Int("current_count", fileCount),
		slog.Int("max_allowed", maxFilesPerDirectory))

	// If we've reached the max, delete the oldest file
	if fileCount >= maxFilesPerDirectory {
		fm.log.Info("Max file limit reached, triggering cleanup",
			slog.String("type", fileType),
			slog.Int("file_count", fileCount))

		if err := fm.deleteOldestFile(dirPath, files, fileType); err != nil {
			return fmt.Errorf("failed to delete oldest file: %w", err)
		}
	}

	return nil
}

// deleteOldestFile finds and deletes the file with the oldest modification time
func (fm *FileManager) deleteOldestFile(dirPath string, entries []os.DirEntry, fileType string) error {
	if len(entries) == 0 {
		fm.log.Warn("No files found to delete", slog.String("type", fileType))
		return nil
	}

	// Get file info with modification times
	var fileInfos []struct {
		name    string
		modTime time.Time
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			fm.log.Warn("Failed to get file info",
				slog.String("type", fileType),
				slog.String("name", entry.Name()),
				slog.String("error", err.Error()))
			continue
		}

		fileInfos = append(fileInfos, struct {
			name    string
			modTime time.Time
		}{
			name:    entry.Name(),
			modTime: info.ModTime(),
		})
	}

	if len(fileInfos) == 0 {
		fm.log.Warn("No regular files found to delete", slog.String("type", fileType))
		return nil
	}

	// Sort by modification time (oldest first)
	sort.Slice(fileInfos, func(i, j int) bool {
		return fileInfos[i].modTime.Before(fileInfos[j].modTime)
	})

	// Delete the oldest file
	oldestFile := fileInfos[0]
	filePath := filepath.Join(dirPath, oldestFile.name)

	if err := os.Remove(filePath); err != nil {
		fm.log.Error("Failed to delete oldest file",
			slog.String("type", fileType),
			slog.String("path", filePath),
			slog.String("error", err.Error()))
		return fmt.Errorf("failed to remove file: %w", err)
	}

	fm.log.Info("Oldest file deleted successfully",
		slog.String("type", fileType),
		slog.String("deleted_file", oldestFile.name),
		slog.String("mod_time", oldestFile.modTime.Format(time.RFC3339)))

	return nil
}

// GetDirectoryStats returns statistics about files in a directory (useful for monitoring)
func (fm *FileManager) GetDirectoryStats(fileType string) (map[string]interface{}, error) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	var subdir string
	switch fileType {
	case "pcap":
		subdir = pcapDir
	case "csv":
		subdir = csvDir
	case "json":
		subdir = jsonDir
	default:
		return nil, fmt.Errorf("invalid file type: %s", fileType)
	}

	dirPath := filepath.Join(fm.baseDir, subdir)

	files, err := os.ReadDir(dirPath)
	if err != nil {
		fm.log.Error("Failed to read directory for stats",
			slog.String("type", fileType),
			slog.String("path", dirPath),
			slog.String("error", err.Error()))
		return nil, err
	}

	var totalSize int64
	var fileList []map[string]interface{}

	for _, entry := range files {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		totalSize += info.Size()
		fileList = append(fileList, map[string]interface{}{
			"name":     entry.Name(),
			"size":     info.Size(),
			"mod_time": info.ModTime().Format(time.RFC3339),
		})
	}

	stats := map[string]interface{}{
		"type":       fileType,
		"path":       dirPath,
		"file_count": len(fileList),
		"total_size": totalSize,
		"max_files":  maxFilesPerDirectory,
		"files":      fileList,
	}

	fm.log.Debug("Directory stats retrieved",
		slog.String("type", fileType),
		slog.Int("file_count", len(fileList)),
		slog.Int64("total_size", totalSize))

	return stats, nil
}
