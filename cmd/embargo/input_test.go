package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilesAreReadInOrderLikeCat(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	first, second, empty := filepath.Join(directory, "first.log"), filepath.Join(directory, "second.log"), filepath.Join(directory, "empty.log")
	for name, content := range map[string]string{first: "one " + filterPAN + "\n", second: "two " + filterEmail, empty: ""} {
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := run([]string{first, empty, second}, strings.NewReader("stdin is ignored\n"), &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if want := "one " + filterMarker + "\ntwo " + filterMarker; out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
	out.Reset()
	if err := run([]string{flagFormat, formatJSON, first, second}, strings.NewReader(""), &out, io.Discard); err != nil || !strings.Contains(out.String(), `"lines": 2`) {
		t.Fatalf("report over files: err=%v output=%s", err, out.String())
	}
}

func TestMissingFileStopsWithoutItsName(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	present := filepath.Join(directory, "present.log")
	if err := os.WriteFile(present, []byte("kept "+filterPAN+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(directory, "private-name.log")
	var out bytes.Buffer
	err := run([]string{present, missing}, strings.NewReader(""), &out, io.Discard)
	if err == nil || err.Error() != "embargo: input file 2 cannot be opened: no such file" || out.String() != "kept "+filterMarker+"\n" {
		t.Fatalf("missing file: err=%v output=%q", err, out.String())
	}
	out.Reset()
	if err := run([]string{flagFormat, formatJSON, missing}, strings.NewReader(""), &out, io.Discard); err == nil || err.Error() != "embargo: input file 1 cannot be opened: no such file" || out.Len() != 0 {
		t.Fatalf("missing file in a report: err=%v output=%q", err, out.String())
	}
	if run([]string{directory}, strings.NewReader(""), &out, io.Discard) == nil {
		t.Fatal("reading a directory must fail")
	}
}

func TestFileBoundaryNeverReadsZeroBytesBeforeTheEnd(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	first, second := filepath.Join(directory, "a.log"), filepath.Join(directory, "b.log")
	for name, content := range map[string]string{first: "ab", second: "cd"} {
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	source, closeAll := openInputs([]string{first, second}, strings.NewReader(""))
	defer closeAll()
	buffer := make([]byte, 16)
	for _, want := range []string{"ab", "cd"} {
		n, err := source.Read(buffer)
		if err != nil || string(buffer[:n]) != want {
			t.Fatalf("Read = %q, %v; want %q", buffer[:n], err, want)
		}
	}
	if n, err := source.Read(buffer); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("after the last file: %d, %v", n, err)
	}
}

func TestDashReadsStdinBetweenFiles(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	first := filepath.Join(directory, "first.log")
	if err := os.WriteFile(first, []byte("file "+filterPAN+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{first, "-", first}, strings.NewReader("stdin "+filterEmail+"\n"), &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if want := "file " + filterMarker + "\nstdin " + filterMarker + "\nfile " + filterMarker + "\n"; out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}

func TestOpenReasonNamesOnlyTheCause(t *testing.T) {
	t.Parallel()
	for err, want := range map[error]string{
		fs.ErrNotExist: ": no such file",
		&fs.PathError{Op: "open", Path: "private-name.log", Err: fs.ErrPermission}: ": permission denied",
		errors.New("private-name.log: invalid argument"):                           "",
	} {
		if got := openReason(err); got != want {
			t.Errorf("openReason(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestUTF16InputStopsInsteadOfPassingThrough(t *testing.T) {
	t.Parallel()
	little, big := "\xff\xfep\x00a\x00n\x00\n\x00", "\xfe\xff\x00p\x00a\x00n\x00\n"
	for _, input := range []string{little, big} {
		var out bytes.Buffer
		if err := run(nil, strings.NewReader(input), &out, io.Discard); err == nil || err.Error() != "embargo: the input is UTF-16; convert it to UTF-8" || out.Len() != 0 {
			t.Errorf("%q: err=%v output=%q", input, err, out.String())
		}
	}
	directory := t.TempDir()
	plain, wide := filepath.Join(directory, "plain.log"), filepath.Join(directory, "wide.log")
	for name, content := range map[string]string{plain: "x\n", wide: little} {
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := run([]string{plain, wide}, strings.NewReader(""), &out, io.Discard); err == nil || err.Error() != "embargo: input file 2 is UTF-16; convert it to UTF-8" || out.String() != "x\n" {
		t.Fatalf("err=%v output=%q", err, out.String())
	}
	for _, input := range []string{"", "x", "\xff"} {
		out.Reset()
		if err := run(nil, strings.NewReader(input), &out, io.Discard); err != nil || out.String() != input {
			t.Errorf("short input %q: err=%v output=%q", input, err, out.String())
		}
	}
}

// invalidGzip is the message for a gzip input that cannot be decompressed.
const invalidGzip = "embargo: the input is not valid gzip"

// gzipped compresses text as one gzip member.
func gzipped(t *testing.T, text string) string {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.String()
}

func TestCompressedInputIsDecompressedOrStops(t *testing.T) {
	t.Parallel()
	// bzip2 of "a alice@example.com\n"; the standard library has no bzip2 writer.
	bzipped, err := base64.StdEncoding.DecodeString("QlpoOTFBWSZTWQv2hswAAAJVgAAQQAFAAComwEAgADEA0AFDExqfqXE6Zy5SXRHIDBdyRThQkAv2hsw=")
	if err != nil {
		t.Fatal(err)
	}
	member := gzipped(t, "one "+filterEmail+"\n")
	lines := make([]string, 20000)
	for i := range lines {
		lines[i] = "line " + strings.Repeat("x", i%50) + "\n"
	}
	large := gzipped(t, strings.Join(lines, ""))
	cases := []struct{ name, input, want, failure string }{
		{"gzip", member, "one " + filterMarker + "\n", ""},
		{"gzip members", member + gzipped(t, "two "+filterPAN+"\n"), "one " + filterMarker + "\ntwo " + filterMarker + "\n", ""},
		{"bzip2", string(bzipped), "a " + filterMarker + "\n", ""},
		{"empty gzip", gzipped(t, ""), "", ""},
		{"broken gzip header", "\x1f\x8bxxxxxxxxxx", "", invalidGzip},
		{"cut gzip", member[:len(member)-6], "", invalidGzip},
		{"cut after the first read", large[:len(large)/2], "", invalidGzip},
		{"broken bzip2", "BZh91AY&SY" + strings.Repeat("x", 40), "", "embargo: the input is not valid bzip2"},
		{"gzip in gzip", gzipped(t, member), "", "embargo: the input is compressed twice; decompress it first"},
		{"UTF-16 in gzip", gzipped(t, "\xff\xfea\x00"), "", "embargo: the input is UTF-16; convert it to UTF-8"},
		{"zstd", "\x28\xb5\x2f\xfd\x00", "", "embargo: the input is zstd-compressed; decompress it first"},
		{"xz", "\xfd7zXZ\x00\x00", "", "embargo: the input is xz-compressed; decompress it first"},
		{"zip", "PK\x03\x04\x14", "", "embargo: the input is zip-compressed; decompress it first"},
		{"7z", "7z\xbc\xaf\x27\x1c\x00", "", "embargo: the input is 7z-compressed; decompress it first"},
		{"lz4", "\x04\x22\x4d\x18\x00", "", "embargo: the input is lz4-compressed; decompress it first"},
	}
	for _, tc := range cases {
		var out bytes.Buffer
		err := run(nil, strings.NewReader(tc.input), &out, io.Discard)
		if tc.failure == "" && (err != nil || out.String() != tc.want) {
			t.Errorf("%s: err=%v output=%q, want %q", tc.name, err, out.String(), tc.want)
		}
		if tc.failure != "" && (err == nil || err.Error() != tc.failure) {
			t.Errorf("%s: err=%v, want %q", tc.name, err, tc.failure)
		}
	}
	// Text that starts like a signature stays text.
	for _, text := range []string{"BZh " + filterEmail + "\n", "BZh91AY&S\n", "BZh01AY&SY\n", "PK\n", "7z\n", "\x1f", "B"} {
		var out bytes.Buffer
		want := strings.ReplaceAll(text, filterEmail, filterMarker)
		if err := run(nil, strings.NewReader(text), &out, io.Discard); err != nil || out.String() != want {
			t.Errorf("%q: err=%v output=%q", text, err, out.String())
		}
	}
	directory := t.TempDir()
	plain, packed := filepath.Join(directory, "plain.log"), filepath.Join(directory, "packed.log.gz")
	for name, content := range map[string]string{plain: "x\n", packed: "\x28\xb5\x2f\xfd"} {
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := run([]string{plain, packed}, strings.NewReader(""), &out, io.Discard); err == nil || err.Error() != "embargo: input file 2 is zstd-compressed; decompress it first" || out.String() != "x\n" {
		t.Fatalf("err=%v output=%q", err, out.String())
	}
}

func TestSniffWaitsOnlyForAPossibleSignature(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		head   string
		chunks []string
	}{
		{"plain line\n", []string{"plain line\n", "more\n"}},
		{"\x1f\x8b", []string{"\x1f", "\x8b", "rest"}},
		{"BZh91AY&SY", []string{"BZ", "h9", "1AY&SY", "data"}},
		{"BZx", []string{"BZ", "x"}},
	} {
		chunks := make([]io.Reader, len(tc.chunks))
		for i, chunk := range tc.chunks {
			chunks[i] = strings.NewReader(chunk)
		}
		head, text, err := sniff(&oneChunkReader{chunks: chunks})
		if err != nil || string(head) != tc.head {
			t.Fatalf("%q: head %q, %v; want %q", tc.chunks, head, err, tc.head)
		}
		all, err := io.ReadAll(text)
		if err != nil || string(all) != strings.Join(tc.chunks, "") {
			t.Fatalf("%q: text %q, %v", tc.chunks, all, err)
		}
	}
	if _, _, err := sniff(&failingInput{}); err == nil {
		t.Fatal("a read failure was not returned")
	}
}

// oneChunkReader returns one chunk per read, as a pipe does.
type oneChunkReader struct{ chunks []io.Reader }

func (r *oneChunkReader) Read(p []byte) (int, error) {
	for len(r.chunks) > 0 {
		n, err := r.chunks[0].Read(p)
		if errors.Is(err, io.EOF) {
			r.chunks = r.chunks[1:]
		}
		if n > 0 {
			return n, nil
		}
	}
	return 0, io.EOF
}
