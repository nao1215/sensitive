package main

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
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
// instead of passing through unmasked. A gzip or bzip2 input is decompressed;
// other compressed formats stop with an error.
func openInputs(names []string, stdin io.Reader) (source io.Reader, closeAll func()) {
	files := &fileSequence{names: names, stdin: stdin, current: nil, file: nil, closeErr: nil, format: "", unnamed: len(names) == 0}
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
	closeErr error
	file     *os.File
	// format names the compression of the current input, if compressed.
	format     string
	names      []string
	opened     int
	started    bool
	unnamed    bool
	compressed bool
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

// readCurrent reads the current input. Its first read decides the format: a
// gzip or bzip2 input is decompressed, as rotated logs are, and a UTF-16 or
// other compressed input stops with an error, since its text would pass
// through unmasked.
func (f *fileSequence) readCurrent(p []byte) (int, error) {
	if !f.started {
		f.started = true
		decoded, err := f.decode(f.current)
		if err != nil {
			return 0, err
		}
		f.current = decoded
	}
	n, err := f.current.Read(p)
	if err != nil && !errors.Is(err, io.EOF) && f.compressed {
		return n, f.failure("is not valid " + f.format)
	}
	return n, err
}

// decode returns input as text, decompressing a gzip or bzip2 stream once.
func (f *fileSequence) decode(input io.Reader) (io.Reader, error) {
	head, text, err := sniff(input)
	if err != nil {
		return nil, err
	}
	switch format := compression(head); format {
	case "":
		return f.checkText(head, text)
	case gzipFormat:
		f.compressed, f.format = true, format
		reader, err := gzip.NewReader(text)
		if err != nil {
			return nil, f.failure("is not valid gzip")
		}
		return f.decodeText(reader)
	case bzip2Format:
		f.compressed, f.format = true, format
		return f.decodeText(bzip2.NewReader(text))
	default:
		return nil, f.failure("is " + format + "-compressed; decompress it first")
	}
}

// decodeText checks decompressed text for UTF-16 and nested compression.
func (f *fileSequence) decodeText(reader io.Reader) (io.Reader, error) {
	head, text, err := sniff(reader)
	if err != nil {
		return nil, f.failure("is not valid " + f.format)
	}
	if compression(head) != "" {
		return nil, f.failure("is compressed twice; decompress it first")
	}
	return f.checkText(head, text)
}

// checkText stops a UTF-16 input, which no detector reads.
func (f *fileSequence) checkText(head []byte, text io.Reader) (io.Reader, error) {
	if bytes.HasPrefix(head, []byte(utf16LittleEndian)) || bytes.HasPrefix(head, []byte(utf16BigEndian)) {
		return nil, f.failure("is UTF-16; convert it to UTF-8")
	}
	return text, nil
}

// sniff reads the first bytes of input, reading more only while they could
// still start a signature, so a short first line of a slow pipe is passed on
// at once. text reads the whole input, head included.
func sniff(input io.Reader) (head []byte, text io.Reader, err error) {
	// The first read keeps all it returns, so a pipe's first line is never split.
	buffer := make([]byte, sniffBytes)
	n := 0
	for n == 0 || (n < signatureBytes && partialSignature(buffer[:n])) {
		read, readErr := input.Read(buffer[n:])
		n += read
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, nil, readErr
		}
	}
	head = buffer[:n]
	return head, io.MultiReader(bytes.NewReader(head), input), nil
}

// failure returns the message for the current input, naming its position
// among the files but never its name.
func (f *fileSequence) failure(problem string) error {
	if f.unnamed {
		return inputError("embargo: the input " + problem)
	}
	return inputError(fmt.Sprintf("embargo: input file %d %s", f.opened, problem))
}

// signatureBytes is the longest signature: "BZh", a block size digit and the
// block magic.
const signatureBytes = 10

// sniffBytes is the most the first read takes before the filter's buffer.
const sniffBytes = 4 << 10

// The UTF-16 byte order marks, little endian first.
const (
	utf16LittleEndian = "\xff\xfe"
	utf16BigEndian    = "\xfe\xff"
)

const (
	gzipFormat  = "gzip"
	bzip2Format = "bzip2"
)

// signature is the start of a compressed format; a '?' in the bzip2 magic is
// its block size digit. A UTF-16 byte order mark has no format name.
type signature struct{ name, magic string }

// signatures lists the formats compression knows.
func signatures() []signature {
	return []signature{
		{gzipFormat, "\x1f\x8b"},
		{bzip2Format, "BZh?1AY&SY"},
		{"zstd", "\x28\xb5\x2f\xfd"},
		{"xz", "\xfd7zXZ\x00"},
		{"zip", "PK\x03\x04"},
		{"7z", "7z\xbc\xaf\x27\x1c"},
		{"lz4", "\x04\x22\x4d\x18"},
		{"", utf16LittleEndian},
		{"", utf16BigEndian},
	}
}

// compression names the format whose signature starts head, or "" for text.
func compression(head []byte) string {
	for _, signature := range signatures() {
		if len(head) >= len(signature.magic) && signatureMatch(head, signature.magic) {
			return signature.name
		}
	}
	return ""
}

// partialSignature reports whether head is shorter than a signature it starts.
func partialSignature(head []byte) bool {
	for _, signature := range signatures() {
		if len(head) < len(signature.magic) && signatureMatch(head, signature.magic) {
			return true
		}
	}
	return false
}

// signatureMatch compares the bytes head and magic have in common.
func signatureMatch(head []byte, magic string) bool {
	for i := range min(len(head), len(magic)) {
		if magic[i] == '?' {
			if head[i] < '1' || head[i] > '9' {
				return false
			}
			continue
		}
		if head[i] != magic[i] {
			return false
		}
	}
	return true
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
	f.current, f.file, f.started, f.compressed, f.format = nil, nil, false, false, ""
}
