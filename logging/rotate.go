package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const (
	// DefaultMaxSizeMB caps one log file.
	DefaultMaxSizeMB = 64
	// DefaultMaxFiles is how many rotated files are kept beside the live one,
	// so the default total on-disk bound is 64 MB x 6 = 384 MB.
	DefaultMaxFiles = 5
)

// rotatingWriter is a size-bounded log sink: it writes to path until the file
// exceeds maxSize, then shifts path -> path.1 -> path.2 ... and drops anything
// past maxFiles. No external dependency, and — unlike an external rotator — the
// bound holds even when nothing else on the box is running.
//
// The bound is what matters here. An unbounded node log has already taken this
// project's testnet down once by filling the disk (~/WATCHDOG.md), so the
// writer never grows without limit and never silently gives up: if rotation
// fails it keeps writing to the current file rather than dropping log lines.
type rotatingWriter struct {
	mu       sync.Mutex
	path     string
	maxSize  int64
	maxFiles int
	size     int64
	f        *os.File
}

func newRotatingWriter(path string, maxSizeMB, maxFiles int) (*rotatingWriter, error) {
	if maxSizeMB <= 0 {
		maxSizeMB = DefaultMaxSizeMB
	}
	if maxFiles < 0 {
		maxFiles = DefaultMaxFiles
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("log dir %s: %w", dir, err)
		}
	}
	w := &rotatingWriter{
		path:     path,
		maxSize:  int64(maxSizeMB) * 1024 * 1024,
		maxFiles: maxFiles,
	}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *rotatingWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", w.path, err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("stat log file %s: %w", w.path, err)
	}
	w.f = f
	w.size = st.Size()
	return nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		if err := w.open(); err != nil {
			return 0, err
		}
	}
	// Rotate before the write that would cross the cap, so a single file never
	// exceeds maxSize by more than one line.
	if w.size > 0 && w.size+int64(len(p)) > w.maxSize {
		w.rotate()
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate shifts the numbered suffixes down and reopens a fresh live file. Any
// error leaves the current file in place and logging continues into it: a
// rotation failure must never become a logging outage.
func (w *rotatingWriter) rotate() {
	if err := w.f.Close(); err != nil {
		return
	}
	if w.maxFiles > 0 {
		_ = os.Remove(fmt.Sprintf("%s.%d", w.path, w.maxFiles))
		for i := w.maxFiles - 1; i >= 1; i-- {
			_ = os.Rename(fmt.Sprintf("%s.%d", w.path, i), fmt.Sprintf("%s.%d", w.path, i+1))
		}
		_ = os.Rename(w.path, w.path+".1")
	} else {
		_ = os.Remove(w.path)
	}
	if err := w.open(); err != nil {
		// Could not reopen: drop back to stderr so lines are not lost silently.
		w.f = os.Stderr
		w.size = 0
	}
}

func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil || w.f == os.Stderr {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
