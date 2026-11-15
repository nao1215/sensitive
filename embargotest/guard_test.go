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
	for _, mode := range []string{safeMode, "stdout", "stderr", "slog", "tlog", "detector", "panic", "subprocess", "overflow", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			cmd := exec.CommandContext(t.Context(), binary)
			cmd.Env = append(os.Environ(), "GUARD_CASE="+mode)
			output, err := cmd.CombinedOutput()
			if (err == nil) != (mode == safeMode) {
				t.Fatalf("wrong verdict: %v %s", err, output)
			}
			if mode == "overflow" || mode == "timeout" {
				if !bytes.Contains(output, []byte("incomplete, truncated or timed out")) {
					t.Fatal("missing incomplete capture diagnosis")
				}
				return
			}
			if mode != safeMode && (!bytes.Contains(output, []byte("TestPackageOutput")) || !bytes.Contains(output, []byte("embargotest: package leak"))) {
				t.Fatalf("missing diagnosis: %s", output)
			}
			if bytes.Contains(output, []byte(defaultCanary)) {
				t.Fatal("guard repeated the canary")
			}
		})
	}
}
