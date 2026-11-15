package output

import (
	"bytes"
	"io"
	"reflect"
	"sync"

	"github.com/nao1215/embargo"
)

// Writer buffers newline-delimited JSON records and forwards only masked events.
// It serializes calls; callers must also serialize writes to the underlying sink
// made outside this adapter. An event is limited to 1 MiB, including its newline.
type Writer struct {
	next    io.Writer
	err     error
	scanner *embargo.Scanner
	pending []byte
	mu      sync.Mutex
	closed  bool
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
// Invalid input or sink failure is sticky; subsequent writes cannot forward raw
// data. Successful n counts input bytes, not the length of the masked output.
func (w *Writer) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	consumed := 0
	for len(data) > 0 {
		end := bytes.IndexByte(data, '\n')
		length := len(data)
		if end >= 0 {
			length = end + 1
		}
		if length > maxEventBytes-len(w.pending) {
			w.err = failure()
			w.pending = nil
			return consumed, w.err
		}
		w.pending = append(w.pending, data[:length]...)
		data = data[length:]
		consumed += length
		if end < 0 {
			continue
		}
		masked, err := JSON(w.pending, w.scanner)
		w.pending = nil
		if err != nil {
			w.err = err
			return consumed, err
		}
		n, err := w.next.Write(masked)
		if err == nil && n != len(masked) {
			err = io.ErrShortWrite
		}
		if err != nil {
			w.err = err
			return consumed, err
		}
	}
	return consumed, nil
}

// Flush validates that no partial record remains. It never sends an unfinished
// record and does not close or synchronize the caller-owned underlying sink.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flush()
}

func (w *Writer) flush() error {
	if w.err != nil {
		return w.err
	}
	if len(w.pending) != 0 {
		w.err = failure()
		w.pending = nil
	}
	return w.err
}

// Close rejects pending partial records and seals the adapter, leaving its sink
// open. It is safe to repeat; the first sticky failure remains observable.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return w.flush()
}
