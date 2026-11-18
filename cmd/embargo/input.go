package main

import (
	"errors"
	"io"
	"os"
)

// stdinName is the file name that reads stdin, as in cat.
const stdinName = "-"

// openInputs reads the named files in order, like cat, or stdin when there are
// none; the name "-" reads stdin in its place. Files open one at a time; a file
// that cannot be read stops the input with a fixed error that does not repeat
// its name.
func openInputs(names []string, stdin io.Reader) (source io.Reader, closeAll func()) {
	if len(names) == 0 {
		return stdin, func() {}
	}
	files := &fileSequence{names: names, stdin: stdin, current: nil, file: nil, closeErr: nil}
	return files, files.close
}

// inputError is a fixed message about the named input files; it never holds a
// file name or operating-system detail, so it is shown as is.
type inputError string

// Error returns the fixed message.
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
}

// Read reads the files in order and reports io.EOF after the last one.
func (f *fileSequence) Read(p []byte) (int, error) {
	for {
		if err := f.advance(); err != nil {
			return 0, err
		}
		n, err := f.current.Read(p)
		if errors.Is(err, io.EOF) {
			// The next file continues the stream, so EOF is reported only after the last.
			f.close()
			if n > 0 {
				return n, nil
			}
			continue
		}
		if err != nil {
			return n, inputError("embargo: an input file cannot be read")
		}
		return n, nil
	}
}

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
	if name == stdinName {
		f.current = f.stdin
		return nil
	}
	// #nosec G304 -- The user names the files to read on the command line.
	file, err := os.Open(name)
	if err != nil {
		return inputError("embargo: an input file cannot be opened")
	}
	f.current, f.file = file, file
	return nil
}

// close releases the current file; a failure is reported by the next Read.
// Stdin belongs to the caller and stays open.
func (f *fileSequence) close() {
	if f.file != nil {
		f.closeErr = f.file.Close()
	}
	f.current, f.file = nil, nil
}
