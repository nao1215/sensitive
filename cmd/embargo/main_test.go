package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestHelpVersionAndExitStatus(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"-h"}, {"--help"}} {
		var out, diagnostics bytes.Buffer
		if code := exitCode(args, strings.NewReader(""), &out, &diagnostics); code != 0 || !strings.HasPrefix(out.String(), "Usage: embargo [") || !strings.Contains(out.String(), flagFormat) || !strings.Contains(out.String(), kindsHelp) {
			t.Errorf("%v: code=%d output=%q", args, code, out.String())
		}
	}
	var out, diagnostics bytes.Buffer
	if code := exitCode([]string{"--version"}, strings.NewReader(""), &out, &diagnostics); code != 0 || !strings.HasPrefix(out.String(), "embargo ") {
		t.Errorf("version: code=%d output=%q", code, out.String())
	}
	out.Reset()
	if code := exitCode([]string{flagKinds, "unknown"}, strings.NewReader(""), &out, &diagnostics); code != statusUsage || out.Len() != 0 || !strings.HasPrefix(diagnostics.String(), "embargo: --kinds") {
		t.Errorf("invalid kind: code=%d stdout=%q stderr=%q", code, out.String(), diagnostics.String())
	}
	if exitCode([]string{flagKinds, "unknown"}, strings.NewReader(""), &out, failingOutput{}) != statusUsage {
		t.Error("a failed diagnostic changed the exit status")
	}
	for _, args := range [][]string{{"--help"}, {"--version"}} {
		if run(args, strings.NewReader(""), failingOutput{}, io.Discard) == nil {
			t.Errorf("%v: output failure ignored", args)
		}
	}
	if writeUsage(&shortWriter{limit: len(usage)}) == nil {
		t.Error("a failure writing the kinds line was ignored")
	}
}

// outputWriteFailed is the fixed error for any failed output write.
const outputWriteFailed = "embargo: output write failed"

// failingInput fails its first read and then ends, so a reader loop that
// ignored the failure would finish with success instead of reading forever.
type failingInput struct{ failed bool }

func (r *failingInput) Read([]byte) (int, error) {
	if r.failed {
		return 0, io.EOF
	}
	r.failed = true
	return 0, errors.New("private-error")
}

type failingOutput struct{}

func (failingOutput) Write([]byte) (int, error) { return 0, errors.New("output closed") }
