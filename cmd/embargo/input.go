package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// stdinName is the file name that reads stdin, as in cat.
const stdinName = "-"

// openInputs reads the named files in order, like cat, or stdin when there are
// none; the name "-" reads stdin in its place. Files open one at a time; a file
// that cannot be read stops the input with an error that gives its position
// among the named files, such as "input file 2 cannot be opened: no such file",
// but does not repeat its name. An input that starts with a UTF-16 byte order
// mark, as Windows PowerShell 5 writes for a redirection, stops with an error
// instead of passing through unmasked.
func openInputs(names []string, stdin io.Reader) (source io.Reader, closeAll func()) {
	files := &fileSequence{names: names, stdin: stdin, current: nil, file: nil, closeErr: nil, unnamed: len(names) == 0}
	if files.unnamed {
		files.names = []string{stdinName}
	}
	return files, files.close
}

// inputError is a message about the named input files; it holds at most a
// file position and a fixed cause, never a file name or operating-system
// detail, so it is shown as is.
type inputError string

// Error returns the message.
func (e inputError) Error() string { return string(e) }

// safeInputError returns err's own message when it is an inputError and
// fallback otherwise, so reader errors from other sources are never shown.
func safeInputError(err error, fallback string) error {
	if message, ok := errors.AsType[inputError](err); ok {
		return message
	}
	return errors.New(fallback)
}

type fileSequence struct {
	stdin    io.Reader
	current  io.Reader
	file     *os.File
	closeErr error
	names    []string
	opened   int
	started  bool
	unnamed  bool
}

// Read reads the files in order and reports io.EOF after the last one.
func (f *fileSequence) Read(p []byte) (int, error) {
	for {
		if err := f.advance(); err != nil {
			return 0, err
		}
		n, err := f.readCurrent(p)
		if failure, ok := errors.AsType[inputError](err); ok {
			return 0, failure
		}
		if errors.Is(err, io.EOF) {
			// The next file continues the stream, so EOF is reported only after the last.
			f.close()
			if n > 0 {
				return n, nil
			}
			continue
		}
		if err != nil && f.unnamed {
			// The filter names the line; stdin's own error text is not shown.
			return n, err
		}
		if err != nil {
			return n, inputError("embargo: an input file cannot be read")
		}
		return n, nil
	}
}

// readCurrent reads the current input, checking its first bytes for a UTF-16
// byte order mark.
func (f *fileSequence) readCurrent(p []byte) (int, error) {
	if f.started || len(p) < len(utf16LittleEndian) {
		return f.current.Read(p)
	}
	f.started = true
	n, err := io.ReadAtLeast(f.current, p, len(utf16LittleEndian))
	if head := string(p[:min(n, len(utf16LittleEndian))]); head == utf16LittleEndian || head == utf16BigEndian {
		if f.unnamed {
			return 0, inputError("embargo: the input is UTF-16; convert it to UTF-8")
		}
		return 0, inputError(fmt.Sprintf("embargo: input file %d is UTF-16; convert it to UTF-8", f.opened))
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		// The short input ends with the next read.
		err = nil
	}
	return n, err
}

// The UTF-16 byte order marks, little endian first.
const (
	utf16LittleEndian = "\xff\xfe"
	utf16BigEndian    = "\xfe\xff"
)

// advance opens the next file when none is open, returning io.EOF after the
// last one and a fixed error for a file that cannot be opened or closed.
func (f *fileSequence) advance() error {
	if f.closeErr != nil {
		return inputError("embargo: an input file cannot be closed")
	}
	if f.current != nil {
		return nil
	}
	if len(f.names) == 0 {
		return io.EOF
	}
	name := f.names[0]
	f.names = f.names[1:]
	f.opened++
	if name == stdinName {
		f.current = f.stdin
		return nil
	}
	// #nosec G304 -- The user names the files to read on the command line.
	file, err := os.Open(name)
	if err != nil {
		return inputError(fmt.Sprintf("embargo: input file %d cannot be opened%s", f.opened, openReason(err)))
	}
	f.current, f.file = file, file
	return nil
}

// openReason names the common causes without the operating-system text,
// which repeats the path.
func openReason(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ": no such file"
	case errors.Is(err, fs.ErrPermission):
		return ": permission denied"
	default:
		return ""
	}
}

// close releases the current file; a failure is reported by the next Read.
// Stdin belongs to the caller and stays open.
func (f *fileSequence) close() {
	if f.file != nil {
		f.closeErr = f.file.Close()
	}
	f.current, f.file, f.started = nil, nil, false
}
