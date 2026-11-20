package main

import (
	"bytes"
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
