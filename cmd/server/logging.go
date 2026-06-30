package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/httplog/v3"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"

	"github.com/txperl/PixivBiu/internal/config"
)

// parseLogLevel converts a config log level string into a slog.Level.
// Shared by newLogger and the log.level reload hook.
func parseLogLevel(s string) (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToUpper(s))); err != nil {
		return 0, fmt.Errorf("invalid log level %q: %w", s, err)
	}
	return level, nil
}

// newLogger builds the slog logger and returns the *slog.LevelVar that
// gates it, so the log.level reload hook can change the level live. The
// handler type is fixed by log.format (restart-required), so only the
// level is adjustable at runtime.
func newLogger(cfg config.LogConfig) (*slog.Logger, *slog.LevelVar, error) {
	level, err := parseLogLevel(cfg.Level)
	if err != nil {
		return nil, nil, err
	}
	levelVar := new(slog.LevelVar)
	levelVar.Set(level)

	opts := &slog.HandlerOptions{
		Level:       levelVar,
		ReplaceAttr: httplog.SchemaECS.ReplaceAttr,
	}

	// The default sink is stdout. When log.file is set, logs go to that
	// size-capped, rotating file *instead of* stdout: a packaged desktop app
	// (the reason this option exists) has no readable console, so teeing to
	// stdout would just write into the void, and a single sink keeps the write
	// path simple. Broken-stdio safety is handled process-wide by
	// suppressSIGPIPE, not here. The path is already anchored to the data root
	// by the caller; desktop builds pass an absolute OS logs path.
	var out io.Writer = os.Stdout
	if cfg.File != "" {
		// Fail fast on a bad log.file rather than silently dropping every line:
		// lumberjack opens the file lazily on first write and slog discards write
		// errors, so without an up-front check a directory or unwritable path
		// would pass boot while no logs land anywhere (stdout is off in this
		// mode). Reject a directory explicitly — the raw open error is opaque
		// ("access denied" on Windows) — then ensure the parent exists and open
		// once to confirm we can write (lumberjack reopens the same path).
		if fi, err := os.Stat(cfg.File); err == nil && fi.IsDir() {
			return nil, nil, fmt.Errorf("log.file %q is a directory, not a file", cfg.File)
		}
		if err := os.MkdirAll(filepath.Dir(cfg.File), 0o755); err != nil {
			return nil, nil, fmt.Errorf("create log dir for %q: %w", cfg.File, err)
		}
		f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("open log.file %q: %w", cfg.File, err)
		}
		_ = f.Close()
		out = &lumberjack.Logger{
			Filename:   cfg.File,
			MaxSize:    10, // megabytes before a rotation
			MaxBackups: 3,
			MaxAge:     30, // days
		}
	}

	var handler slog.Handler
	switch strings.ToLower(cfg.Format) {
	case "json":
		handler = slog.NewJSONHandler(out, opts)
	case "", "text":
		handler = slog.NewTextHandler(out, opts)
	default:
		return nil, nil, fmt.Errorf("invalid log format %q (want text|json)", cfg.Format)
	}
	return slog.New(handler), levelVar, nil
}
