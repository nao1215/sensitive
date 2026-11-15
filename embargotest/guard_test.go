package embargotest

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

//nolint:goconst // Keep child modes and their expected diagnostics together.
func TestPackageGuard(t *testing.T) {
	t.Parallel()
	const safeMode = "safe"
	binary := filepath.Join(t.TempDir(), "guard.test.exe")
	// #nosec G204 -- Fixed Go command and test package, output path from TempDir.
	build := exec.CommandContext(t.Context(), "go", "test", "-c", "-o", binary, "./testdata/guard")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	for _, mode := range []string{safeMode, "stdout", "stderr", "slog", "tlog", "detector", "subtest", "panic", "subprocess", "overflow", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			args := []string{}
			if mode == "stdout" {
				args = append(args, "-test.run=^TestPackageOutput$")
			}
			// #nosec G204 -- The binary is built above; arguments select a fixed fixture test.
			cmd := exec.CommandContext(t.Context(), binary, args...)
			cmd.Env = append(os.Environ(), "GUARD_CASE="+mode)
			output, err := cmd.CombinedOutput()
			if (err == nil) != (mode == safeMode) {
				t.Fatalf("wrong verdict: %v %s", err, output)
			}
			if incompleteGuardMode(mode) {
				if !bytes.Contains(output, []byte("incomplete, truncated or timed out")) {
					t.Fatal("missing incomplete capture diagnosis")
				}
				return
			}
			if mode != safeMode && (!bytes.Contains(output, []byte("active tests:")) || !bytes.Contains(output, []byte("embargotest: package leak"))) {
				t.Fatalf("missing diagnosis: %s", output)
			}
			if mode == "subtest" && !bytes.Contains(output, []byte("TestPackageOutput/leaking_child")) {
				t.Fatalf("missing leaking subtest name: %s", output)
			}
			if mode == "stdout" {
				checkGuardSnapshot(t, output)
			}
			if bytes.Contains(output, []byte(defaultCanary)) {
				t.Fatal("guard repeated the canary")
			}
		})
	}
	testGuardArguments(t, binary)
}

func testGuardArguments(t *testing.T, binary string) {
	t.Helper()
	for _, args := range [][]string{{"positional"}, {"-test.v=test2json"}} {
		t.Run(args[0], func(t *testing.T) {
			t.Parallel()
			// #nosec G204 -- Built test fixture, fixed case arguments, no shell.
			cmd := exec.CommandContext(t.Context(), binary, args...)
			cmd.Env = append(os.Environ(), "GUARD_CASE=safe")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child failed: %v %s", err, out)
			}
			if !bytes.Contains(out, []byte("=== RUN")) {
				t.Error("positional argument disabled verbose capture")
			}
			if args[0] == "-test.v=test2json" && !bytes.Contains(out, []byte{0x16}) {
				t.Error("test2json framing was lost")
			}
		})
	}
}

func checkGuardSnapshot(t *testing.T, output []byte) {
	t.Helper()
	for line := range bytes.SplitSeq(output, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("embargotest: package leak")) {
			continue
		}
		want, err := os.ReadFile("testdata/guard-failure.golden")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(append(bytes.Clone(line), '\n'), want) {
			t.Fatal("Guard diagnostic snapshot changed")
		}
		return
	}
	t.Fatal("Guard diagnostic missing")
}

func incompleteGuardMode(mode string) bool { return mode == "overflow" || mode == "timeout" }
