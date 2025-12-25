package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SQLiteRecord represents a single match record
type SQLiteRecord struct {
	ID        int64    `json:"id"`
	ScanID    int64    `json:"scan_id"`
	Timestamp string   `json:"timestamp"`
	File      string   `json:"file"`
	Pattern   string   `json:"pattern"`
	Match     string   `json:"match"`
	Context   string   `json:"context"`
	Decoders  []string `json:"decoders"`
	Offset    int      `json:"offset"`
}

// SQLiteDatabase represents a JSON-based database
type SQLiteDatabase struct {
	path    string
	Scans   []ScanInfo     `json:"scans"`
	Records []SQLiteRecord `json:"records"`
}

// ScanInfo contains metadata about a scan
type ScanInfo struct {
	ID        int64    `json:"id"`
	Timestamp string   `json:"timestamp"`
	Pattern   string   `json:"pattern"`
	Paths     []string `json:"paths"`
	Options   string   `json:"options"`
}

// OpenDatabase opens or creates a JSON database
func OpenDatabase(path string) (*SQLiteDatabase, error) {
	db := &SQLiteDatabase{
		path:    path,
		Scans:   make([]ScanInfo, 0),
		Records: make([]SQLiteRecord, 0),
	}

	// Try to load existing database
	if data, err := os.ReadFile(path); err == nil {
		json.Unmarshal(data, db)
	}

	return db, nil
}

// Save saves the database to disk
func (db *SQLiteDatabase) Save() error {
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(db.path, data, 0644)
}

// AddScan adds a new scan record
func (db *SQLiteDatabase) AddScan(pattern string, paths []string, options string) int64 {
	id := int64(len(db.Scans) + 1)
	db.Scans = append(db.Scans, ScanInfo{
		ID:        id,
		Timestamp: time.Now().Format(time.RFC3339),
		Pattern:   pattern,
		Paths:     paths,
		Options:   options,
	})
	return id
}

// AddRecord adds a match record
func (db *SQLiteDatabase) AddRecord(scanID int64, file, pattern, match, context string, decoders []string, offset int) {
	id := int64(len(db.Records) + 1)
	db.Records = append(db.Records, SQLiteRecord{
		ID:        id,
		ScanID:    scanID,
		Timestamp: time.Now().Format(time.RFC3339),
		File:      file,
		Pattern:   pattern,
		Match:     match,
		Context:   context,
		Decoders:  decoders,
		Offset:    offset,
	})
}

// WatchMode monitors a directory for changes and re-scans
type WatchMode struct {
	paths       []string
	pattern     string
	searcher    *Searcher
	interval    time.Duration
	running     bool
	lastModTime map[string]time.Time
}

// NewWatchMode creates a new watch mode handler
func NewWatchMode(paths []string, pattern string, searcher *Searcher, interval time.Duration) *WatchMode {
	return &WatchMode{
		paths:       paths,
		pattern:     pattern,
		searcher:    searcher,
		interval:    interval,
		running:     true,
		lastModTime: make(map[string]time.Time),
	}
}

// Run starts the watch loop
func (w *WatchMode) Run() error {
	fmt.Printf("Watching for changes (interval: %v)...\n", w.interval)
	fmt.Println("Press Ctrl+C to stop")

	// Initial scan
	w.scanAll()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for w.running {
		<-ticker.C
		w.checkForChanges()
	}

	return nil
}

// Stop stops the watch mode
func (w *WatchMode) Stop() {
	w.running = false
}

func (w *WatchMode) scanAll() {
	for _, path := range w.paths {
		filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() {
				w.lastModTime[p] = info.ModTime()
			}
			return nil
		})
	}

	w.searcher.Run()
}

func (w *WatchMode) checkForChanges() {
	changed := false

	for _, path := range w.paths {
		filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}

			lastMod, exists := w.lastModTime[p]
			if !exists || info.ModTime().After(lastMod) {
				changed = true
				w.lastModTime[p] = info.ModTime()
				fmt.Printf("\n[CHANGE] %s modified at %s\n", p, info.ModTime().Format("15:04:05"))
			}
			return nil
		})
	}

	if changed {
		fmt.Println("[SCAN] Re-scanning...")
		w.searcher.Run()
	}
}

// FormatSize formats a byte size to human readable format
func FormatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
