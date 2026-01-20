package fileops

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"

	"github.com/Vadym-H/GoSniffer/internal/lib/logger/sl"
)

// CaptureFile represents a captured file
type CaptureFile struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified"`
	Type     string `json:"type"` // pcap, csv, json
}

// FileOpsHandler handles file listing and download operations
type FileOpsHandler struct {
	log              *slog.Logger
	capturesBasePath string
}

// NewFileOpsHandler creates a new file operations handler
func NewFileOpsHandler(log *slog.Logger, capturesBasePath string) *FileOpsHandler {
	return &FileOpsHandler{
		log:              log,
		capturesBasePath: capturesBasePath,
	}
}

// ListCaptures handles GET /sniffer/captures
func (h *FileOpsHandler) ListCaptures(w http.ResponseWriter, _ *http.Request) {
	files := []CaptureFile{}

	formats := []string{"pcap", "csv", "json"}

	for _, format := range formats {
		formatPath := filepath.Join(h.capturesBasePath, format)

		entries, err := os.ReadDir(formatPath)
		if err != nil {
			h.log.Warn("Failed to read directory",
				slog.String("path", formatPath),
				sl.Err(err),
			)
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				h.log.Warn("Failed to read file info",
					slog.String("file", entry.Name()),
					sl.Err(err),
				)
				continue
			}

			files = append(files, CaptureFile{
				Name:     info.Name(),
				Size:     info.Size(),
				Modified: info.ModTime().Unix(),
				Type:     format,
			})
		}
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Modified > files[j].Modified
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"total_files": len(files),
		"files":       files,
	}); err != nil {
		h.log.Error("Failed to encode captures list", sl.Err(err))
	}
}

// DownloadCapture handles GET /sniffer/captures/download/*
func (h *FileOpsHandler) DownloadCapture(w http.ResponseWriter, r *http.Request) {
	filename := filepath.Base(r.URL.Path)

	if filename == "" || filename == "." || filename == "/" {
		http.Error(w, "Filename required", http.StatusBadRequest)
		return
	}

	var err error
	filename, err = url.PathUnescape(filename)
	if err != nil {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	formats := []string{"pcap", "csv", "json"}
	var filePath string

	for _, format := range formats {
		candidate := filepath.Join(h.capturesBasePath, format, filename)
		if _, err := os.Stat(candidate); err == nil {
			filePath = candidate
			break
		}
	}

	if filePath == "" {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	absBaseDir, _ := filepath.Abs(h.capturesBasePath)
	if !isPathSafe(absPath, absBaseDir) {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	w.Header().Set(
		"Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s"`, filename),
	)

	http.ServeFile(w, r, filePath)

	h.log.Info("File downloaded", slog.String("filename", filename))
}

// getContentType returns appropriate content type for a file
func getContentType(filename string) string {
	ext := filepath.Ext(filename)
	switch ext {
	case ".pcap":
		return "application/octet-stream"
	case ".csv":
		return "text/csv"
	case ".json":
		return "application/json"
	default:
		return "application/octet-stream"
	}
}

// isPathSafe checks if a path is within the base directory
func isPathSafe(path, baseDir string) bool {
	rel, err := filepath.Rel(baseDir, path)
	if err != nil {
		return false
	}
	// Check for directory traversal attempts
	return !filepath.IsAbs(rel) && rel != ".." && rel[:3] != ".."
}
