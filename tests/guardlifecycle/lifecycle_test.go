package guardlifecycle_test

import (
	"os"
	"testing"

	"go.uber.org/goleak"

	"github.com/nao1215/embargo/embargotest"
)

func TestMain(m *testing.M) {
	code := embargotest.Guard(m)
	if err := goleak.Find(); err != nil {
		if _, writeErr := os.Stderr.WriteString("guard left goroutines running\n"); writeErr != nil {
			os.Exit(1)
		}
		code = 1
	}
	os.Exit(code)
}

func TestGuardParallel(t *testing.T) { t.Parallel(); t.Log("safe lifecycle output") }
