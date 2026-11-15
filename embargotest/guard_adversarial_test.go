package embargotest

import (
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

func TestGuardForgedTestNamesNeverReachDiagnostics(t *testing.T) {
	t.Parallel()
	const attacker = "opaque-private-value-not-known-to-detectors"
	for _, prefix := range []string{"=== RUN   ", "\x16=== RUN   "} {
		data := []byte(prefix + attacker + "\n" + defaultCanary)
		got := guardTests(&guardCapture{data: [2][]byte{data, nil}}, 0, []embargo.Finding{{Start: len(prefix) + len(attacker) + 1, End: len(data)}}, guardPolicy([]Option{WithCanary([]byte(attacker))}))
		if strings.Contains(got, attacker) {
			t.Fatal("untrusted stream framing echoed input into a Guard diagnostic")
		}
	}
}
