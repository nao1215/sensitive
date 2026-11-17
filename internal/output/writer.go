package output

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"sync"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/saferecord"
)

// Writer buffers newline-delimited JSON records and forwards only masked events.
// It serializes sink writes and fragment buffering, while whole events from
// concurrent calls are masked in parallel; callers must also serialize writes to
// the underlying sink made outside this adapter. An event is limited to 1 MiB, including its newline.
type Writer struct {
	next      io.Writer
	err       error
	scanner   *embargo.Scanner
	pending   []byte
	metadata  eventMetadata
	oversized bool
	mu        sync.Mutex
	closed    bool
}

// Require rejects nil or typed-nil dependencies using a fixed panic message.
func Require(value any) {
	if value == nil {
		panic("embargo: nil logger adapter dependency")
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if v.IsNil() {
			panic("embargo: nil logger adapter dependency")
		}
	case reflect.Invalid, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr, reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.Array, reflect.String, reflect.Struct, reflect.UnsafePointer:
	}
}

// NewWriter requires an output sink and an explicit scanner policy.
func NewWriter(next io.Writer, scanner *embargo.Scanner) *Writer {
	Require(next)
	Require(scanner)
	return &Writer{next: next, scanner: scanner}
}

// Write retains split records until a newline and masks each complete JSON event.
// Masking failures emit a fixed diagnostic and processing resumes at the next
// newline. Only sink failures are sticky. Successful n counts consumed input
// bytes, including withheld input, not the length of the masked output.
func (w *Writer) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.usable(); err != nil {
		return 0, err
	}
	if w.whole(data) {
		return w.writeWhole(data)
	}
	consumed := 0
	for len(data) > 0 {
		end := bytes.IndexByte(data, '\n')
		length := len(data)
		if end >= 0 {
			length = end + 1
		}
		w.retain(data[:length])
		data = data[length:]
		consumed += length
		if end < 0 {
			continue
		}
		masked := w.event()
		if err := w.send(masked); err != nil {
			return consumed, err
		}
	}
	return consumed, nil
}

func (w *Writer) usable() error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return io.ErrClosedPipe
	}
	return nil
}

// whole reports a write that is exactly one event within the size limit while
// no fragment is pending, which is how zap and zerolog call Write.
func (w *Writer) whole(data []byte) bool {
	end := bytes.IndexByte(data, '\n')
	return len(w.pending) == 0 && !w.oversized && end >= 0 && end == len(data)-1 && len(data) <= maxEventBytes
}

// writeWhole masks one event without holding the lock, so goroutines that log
// at the same time mask in parallel and only the sink write is serialized. A
// Close or sink failure that happens meanwhile wins and the event is dropped.
func (w *Writer) writeWhole(data []byte) (int, error) {
	masked := func() []byte {
		w.mu.Unlock()
		defer w.mu.Lock()
		return maskEvent(data, w.scanner)
	}()
	if err := w.usable(); err != nil {
		return 0, err
	}
	if err := w.send(masked); err != nil {
		return len(data), err
	}
	return len(data), nil
}

func maskEvent(data []byte, scanner *embargo.Scanner) []byte {
	masked, err := JSON(data, scanner)
	if err != nil {
		var metadata eventMetadata
		metadata.feed(data)
		return metadata.fallback(saferecord.Reason(context.Background(), err))
	}
	return masked
}

// retain buffers part of the current record. A record that would exceed the
// event limit switches to metadata observation and keeps no further bytes.
func (w *Writer) retain(part []byte) {
	if !w.oversized && len(part) > maxEventBytes-len(w.pending) {
		w.metadata.feed(w.pending)
		w.oversized = true
		w.pending = nil
	}
	if w.oversized {
		w.metadata.feed(part)
	}
	if !w.oversized {
		w.pending = append(w.pending, part...)
	}
}

func (w *Writer) event() []byte {
	defer func() { w.pending = nil; w.metadata = eventMetadata{}; w.oversized = false }()
	if w.oversized {
		return w.metadata.fallback(saferecord.ErrSizeLimit)
	}
	return maskEvent(w.pending, w.scanner)
}

func (w *Writer) send(data []byte) error {
	n, err := w.next.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	w.err = err
	return err
}

// Flush replaces a pending fragment with a diagnostic and returns a framing
// error. It does not close or synchronize the caller-owned underlying sink.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flush()
}

// FlushSync flushes like Flush and then calls syncSink while still holding the
// lock, so a sink's Sync never runs during one of its Writes.
func (w *Writer) FlushSync(syncSink func() error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return errors.Join(w.flush(), syncSink())
}

func (w *Writer) flush() error {
	if w.err != nil {
		return w.err
	}
	if len(w.pending) != 0 || w.oversized {
		reason := saferecord.ErrMasking
		if w.oversized {
			reason = saferecord.ErrSizeLimit
		}
		if !w.oversized {
			w.metadata.feed(w.pending)
		}
		data := w.metadata.fallback(reason)
		w.pending = nil
		w.metadata = eventMetadata{}
		w.oversized = false
		if err := w.send(data); err != nil {
			return err
		}
		return failure()
	}
	return w.err
}

// Close diagnoses pending partial records and seals the adapter, leaving its sink
// open. It is safe to repeat; sink failures remain observable.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return w.flush()
}
