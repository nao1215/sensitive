package main

import (
	"bytes"
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
	if err := run([]string{first, empty, second}, strings.NewReader("stdin is ignored\n"), &out); err != nil {
		t.Fatal(err)
	}
	if want := "one " + filterMarker + "\ntwo " + filterMarker; out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
	out.Reset()
	if err := run([]string{"audit", first, second}, strings.NewReader(""), &out); err != nil || !strings.Contains(out.String(), `"lines": 2`) {
		t.Fatalf("audit over files: err=%v output=%s", err, out.String())
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
	err := run([]string{present, missing}, strings.NewReader(""), &out)
	if err == nil || strings.Contains(err.Error(), "private-name") || out.String() != "kept "+filterMarker+"\n" {
		t.Fatalf("missing file: err=%v output=%q", err, out.String())
	}
	if run([]string{directory}, strings.NewReader(""), &out) == nil {
		t.Fatal("reading a directory must fail")
	}
}

func TestHelpVersionAndExitStatus(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"-h"}, {"--help"}} {
		var out, diagnostics bytes.Buffer
		if code := exitCode(args, strings.NewReader(""), &out, &diagnostics); code != 0 || !strings.HasPrefix(out.String(), "Usage: embargo [") || !strings.Contains(out.String(), "embargo audit") || !strings.Contains(out.String(), kindsHelp) {
			t.Errorf("%v: code=%d output=%q", args, code, out.String())
		}
	}
	var out, diagnostics bytes.Buffer
	if code := exitCode([]string{"--version"}, strings.NewReader(""), &out, &diagnostics); code != 0 || !strings.HasPrefix(out.String(), "embargo ") {
		t.Errorf("version: code=%d output=%q", code, out.String())
	}
	out.Reset()
	if code := exitCode([]string{"--kinds", "unknown"}, strings.NewReader(""), &out, &diagnostics); code != 1 || out.Len() != 0 || !strings.HasPrefix(diagnostics.String(), "embargo: --kinds") {
		t.Errorf("invalid kind: code=%d stdout=%q stderr=%q", code, out.String(), diagnostics.String())
	}
	if exitCode([]string{"--kinds", "unknown"}, strings.NewReader(""), &out, failingOutput{}) != 1 {
		t.Error("a failed diagnostic changed the exit status")
	}
	for _, args := range [][]string{{"--help"}, {"--version"}} {
		if run(args, strings.NewReader(""), failingOutput{}) == nil {
			t.Errorf("%v: output failure ignored", args)
		}
	}
	if writeUsage(&shortWriter{limit: len(filterUsage)}, filterUsage) == nil {
		t.Error("a failure writing the kinds line was ignored")
	}
}

func TestParseConfidenceBounds(t *testing.T) {
	t.Parallel()
	for text, want := range map[string]bool{"0": true, "1": true, "0.5": true, "-0.01": false, "1.01": false, "NaN": false, "high": false} {
		if _, ok := parseConfidence(text); ok != want {
			t.Errorf("parseConfidence(%q) ok = %v, want %v", text, ok, want)
		}
	}
}
