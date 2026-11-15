package tests

import (
	"os/exec"
	"testing"
)

func TestComparisonDocuments(t *testing.T) {
	t.Parallel()
	command := exec.CommandContext(t.Context(), "python3", "scripts/comparison_docs.py", "--check")
	command.Dir = ".."
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("comparison artifacts: %v\n%s", err, output)
	}
}
