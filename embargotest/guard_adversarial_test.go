package embargotest

import (
	"strings"
	"testing"
)

func TestGuardForgedTestNamesNeverReachDiagnostics(t *testing.T) {
	t.Parallel()
	const attacker = "opaque-private-value-not-known-to-detectors"
	for _, prefix := range []string{"=== RUN   ", "\x16=== RUN   "} {
		got := guardTests([]byte(prefix + attacker + "\n"))
		if strings.Contains(got, attacker) {
			t.Fatal("untrusted stream framing echoed input into a Guard diagnostic")
		}
	}
}
