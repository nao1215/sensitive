package embargozap

import (
	"go.uber.org/zap/zapcore"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/output"
)

// NewWriteSyncer masks complete JSON events from a zap JSON encoder.
// Both dependencies are required; nil dependencies panic.
// Write and Sync serialize access to next, so wrapping it in zapcore.Lock is not
// needed; whole entries from concurrent goroutines are masked in parallel. Sync emits diagnostics for incomplete
// events and synchronizes the sink even when framing failed. Masking failures emit a diagnostic retaining
// recognized level metadata, a fixed reason and withheld_attributes. Input timestamps are omitted because their encoder origin cannot be proven. No
// original fields survive; subsequent complete events remain usable. See package limits.
func NewWriteSyncer(next zapcore.WriteSyncer, scanner *embargo.Scanner) zapcore.WriteSyncer {
	return &writeSyncer{writer: output.NewWriter(next, scanner), next: next}
}

type writeSyncer struct {
	writer *output.Writer
	next   zapcore.WriteSyncer
}

// Write buffers split events until a complete JSON line can be checked.
func (w *writeSyncer) Write(data []byte) (int, error) {
	return w.writer.Write(data)
}

// Sync forwards pending diagnostics, synchronizes the sink and joins both errors.
func (w *writeSyncer) Sync() error {
	return w.writer.FlushSync(w.next.Sync)
}
