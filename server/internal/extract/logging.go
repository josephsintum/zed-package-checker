package extract

import (
	"context"
	"fmt"
	"log/slog"

	scalibrlog "github.com/google/osv-scalibr/log"
)

// SetLogger routes osv-scalibr's logging into l.
//
// scalibr keeps its logger in a package-level global, so this affects the whole
// process and should be called once during startup. Left unset, scalibr writes
// its own unstructured lines to stderr, which land in the editor's LSP log
// mixed in with ours.
func SetLogger(l *slog.Logger) {
	scalibrlog.SetLogger(&slogBridge{log: l})
}

// slogBridge adapts scalibr's printf-style Logger to slog.
//
// Levels are deliberately lowered by one step: scalibr logs routine progress
// ("Starting filesystem walk", per-file extraction results) at Info, which is
// per-scan noise rather than something a user needs to see. Its warnings are
// usually unreadable or unsupported files, which are expected in a tree we do
// not control.
type slogBridge struct{ log *slog.Logger }

func (b *slogBridge) Errorf(format string, args ...any) { b.logf(slog.LevelWarn, format, args...) }
func (b *slogBridge) Error(args ...any)                 { b.logln(slog.LevelWarn, args...) }
func (b *slogBridge) Warnf(format string, args ...any)  { b.logf(slog.LevelDebug, format, args...) }
func (b *slogBridge) Warn(args ...any)                  { b.logln(slog.LevelDebug, args...) }
func (b *slogBridge) Infof(format string, args ...any)  { b.logf(slog.LevelDebug, format, args...) }
func (b *slogBridge) Info(args ...any)                  { b.logln(slog.LevelDebug, args...) }
func (b *slogBridge) Debugf(format string, args ...any) { b.logf(slog.LevelDebug, format, args...) }
func (b *slogBridge) Debug(args ...any)                 { b.logln(slog.LevelDebug, args...) }

func (b *slogBridge) logf(level slog.Level, format string, args ...any) {
	// Skip formatting entirely when the level is disabled: scalibr calls these
	// once per file, and a scan can touch tens of thousands.
	if !b.log.Enabled(context.Background(), level) {
		return
	}
	b.log.Log(context.Background(), level, fmt.Sprintf(format, args...), "component", "scalibr")
}

func (b *slogBridge) logln(level slog.Level, args ...any) {
	if !b.log.Enabled(context.Background(), level) {
		return
	}
	b.log.Log(context.Background(), level, fmt.Sprint(args...), "component", "scalibr")
}
