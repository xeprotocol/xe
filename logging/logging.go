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

type Config struct {
	Level string

	File string

	MaxSizeMB int

	MaxFiles int

	JSON bool
}

var (
	levelVar  = new(slog.LevelVar)
	current   atomic.Int32
	logger    atomic.Pointer[slog.Logger]
	initiated atomic.Bool
)

func init() {
	levelVar.Set(slog.LevelInfo)
	current.Store(int32(LevelInfo))
	logger.Store(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: levelVar})))
}

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

	log.SetFlags(0)
	log.SetPrefix("")
	log.SetOutput(legacyWriter{})
	initiated.Store(true)

	return closer, nil
}

type legacyWriter struct{}

func (legacyWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	if msg != "" {
		logger.Load().Info(msg)
	}
	return len(p), nil
}

func Initialized() bool { return initiated.Load() }

func SetLevel(l Level) {
	levelVar.Set(l.slog())
	current.Store(int32(l))
}

func GetLevel() Level { return Level(current.Load()) }

func Enabled(l Level) bool { return l >= GetLevel() }

func Logger() *slog.Logger { return logger.Load() }

func Debugf(format string, v ...any) { logf(LevelDebug, format, v...) }
func Infof(format string, v ...any)  { logf(LevelInfo, format, v...) }
func Warnf(format string, v ...any)  { logf(LevelWarn, format, v...) }
func Errorf(format string, v ...any) { logf(LevelError, format, v...) }

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
