package embargozap

import (
	"sync"

	"go.uber.org/zap/zapcore"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/output"
)

// NewWriteSyncer masks complete JSON events from a zap JSON encoder.
// Both dependencies are required; nil dependencies panic.
// Write and Sync serialize access to next, and Sync rejects incomplete events
// before delegating synchronization. See the package documentation for limits.
func NewWriteSyncer(next zapcore.WriteSyncer, scanner *embargo.Scanner) zapcore.WriteSyncer {
	return &writeSyncer{writer: output.NewWriter(next, scanner), next: next}
}

type writeSyncer struct {
	writer *output.Writer
	next   zapcore.WriteSyncer
	mu     sync.Mutex
}

// Write buffers split events until a complete JSON line can be checked.
func (w *writeSyncer) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(data)
}

// Sync rejects an incomplete event before flushing the downstream sink.
func (w *writeSyncer) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.writer.Flush(); err != nil {
		return err
	}
	return w.next.Sync()
}
