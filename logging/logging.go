// Package logging provides levelled, size-bounded logging for the xe node.
//
// Two problems motivated it (#841):
//
//  1. There were no log levels at all — 246 unconditional log.Printf calls, so
//     an operator had no way to turn the volume down from source or from
//     tracked configuration.
//  2. There was no rotation. The project has a documented disk-full outage on
//     record (46 GB of unbounded node logs) that broke authentication for about
//     a week.
//
// Init addresses both at once. It installs a levelled slog handler AND
// redirects the standard library's log package into the same handler, so every
// legacy log.Printf in the tree is levelled (at info) and written to the same
// size-bounded sink without having to be converted first. Converting a call
// site to logging.Debugf/Warnf/Errorf then moves it off the info default and
// makes it individually controllable.
package logging

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
)

// Level is a log severity. The zero value is LevelDebug; use ParseLevel.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return fmt.Sprintf("level(%d)", int(l))
	}
}

func (l Level) slog() slog.Level {
	switch l {
	case LevelDebug:
		return slog.LevelDebug
	case LevelWarn:
		return slog.LevelWarn
	case LevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// ParseLevel maps a flag value to a Level. It is strict: an unrecognised value
// is an error rather than a silent fallback, so a typo in a deployment unit
// fails the node at startup instead of quietly selecting a level the operator
// did not ask for.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug, nil
	case "", "info":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelInfo, fmt.Errorf("unknown log level %q (want debug|info|warn|error)", s)
	}
}

// Config configures the process logger.
type Config struct {
	// Level is one of debug|info|warn|error. Empty means info.
	Level string
	// File, when non-empty, sends every log line to a size-bounded rotating
	// file instead of stderr. Under a supervisor that already captures stderr
	// (pm2, systemd/journald) leaving this empty is fine ONLY if that
	// supervisor caps its own log size — otherwise set it.
	File string
	// MaxSizeMB caps a single log file. 0 = DefaultMaxSizeMB.
	MaxSizeMB int
	// MaxFiles is how many rotated files are retained alongside the live one.
	// 0 = DefaultMaxFiles. Total on-disk bound is MaxSizeMB*(MaxFiles+1).
	MaxFiles int
	// JSON selects the slog JSON handler instead of the text handler.
	JSON bool
}

var (
	levelVar  = new(slog.LevelVar)
	current   atomic.Int32 // Level
	logger    atomic.Pointer[slog.Logger]
	initiated atomic.Bool
)

func init() {
	levelVar.Set(slog.LevelInfo)
	current.Store(int32(LevelInfo))
	logger.Store(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: levelVar})))
}

// Init configures the process-wide logger and bridges the standard library log
// package into it. The returned io.Closer closes the rotating file, if one was
// opened; it is nil-safe to ignore for stderr logging.
//
// Init is intended to be called once, early, from main.
func Init(cfg Config) (io.Closer, error) {
	lvl, err := ParseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}

	var (
		w      io.Writer = os.Stderr
		closer io.Closer
	)
	if cfg.File != "" {
		rw, err := newRotatingWriter(cfg.File, cfg.MaxSizeMB, cfg.MaxFiles)
		if err != nil {
			return nil, err
		}
		w, closer = rw, rw
	}

	levelVar.Set(lvl.slog())
	current.Store(int32(lvl))

	opts := &slog.HandlerOptions{Level: levelVar}
	var h slog.Handler
	if cfg.JSON {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	l := slog.New(h)
	logger.Store(l)
	slog.SetDefault(l)

	// Bridge the standard library. Every unconverted log.Printf in the tree
	// now lands in this handler at info level, which means --log-level=warn
	// silences all of them and --log-file bounds all of them. Flags are
	// cleared so the stdlib does not prepend a second timestamp in front of
	// slog's own.
	log.SetFlags(0)
	log.SetPrefix("")
	log.SetOutput(legacyWriter{})
	initiated.Store(true)

	return closer, nil
}

// legacyWriter forwards standard-library log output into slog at info level.
type legacyWriter struct{}

func (legacyWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	if msg != "" {
		logger.Load().Info(msg)
	}
	return len(p), nil
}

// Initialized reports whether Init has run. Before that the logger writes
// text at info level to stderr and the standard library is not yet bridged.
func Initialized() bool { return initiated.Load() }

// SetLevel changes the active level at runtime.
func SetLevel(l Level) {
	levelVar.Set(l.slog())
	current.Store(int32(l))
}

// GetLevel reports the active level.
func GetLevel() Level { return Level(current.Load()) }

// Enabled reports whether a message at level l would be emitted. Use it to
// guard expensive message construction on hot paths.
func Enabled(l Level) bool { return l >= GetLevel() }

// Logger returns the underlying slog logger for structured call sites.
func Logger() *slog.Logger { return logger.Load() }

func Debugf(format string, v ...any) { logf(LevelDebug, format, v...) }
func Infof(format string, v ...any)  { logf(LevelInfo, format, v...) }
func Warnf(format string, v ...any)  { logf(LevelWarn, format, v...) }
func Errorf(format string, v ...any) { logf(LevelError, format, v...) }

// Fatalf logs at error level and exits(1). Prefer it over log.Fatalf so the
// message survives --log-level=error and reaches the configured sink.
func Fatalf(format string, v ...any) {
	logf(LevelError, format, v...)
	os.Exit(1)
}

func logf(l Level, format string, v ...any) {
	if !Enabled(l) {
		return
	}
	logger.Load().Log(context.Background(), l.slog(), fmt.Sprintf(format, v...))
}
