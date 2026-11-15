package tests

import (
	"os/exec"
	"testing"
)

func TestRealLogDocuments(t *testing.T) {
	t.Parallel()
	for _, script := range []string{"scripts/real_logs.py", "scripts/scanner_experiment.py"} {
		// #nosec G204 -- Script is selected from the two fixed repository paths above.
		command := exec.CommandContext(t.Context(), "python3", script, "--check")
		command.Dir = ".."
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", script, err, output)
		}
	}
}
