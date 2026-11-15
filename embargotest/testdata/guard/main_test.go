package guard_test

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

func TestMain(m *testing.M) {
	opts := []embargotest.Option{embargotest.WithScanner(embargo.NewScanner(embargo.WithKinds(embargo.KindCredential)))}
	switch os.Getenv("GUARD_CASE") {
	case "overflow":
		opts = append(opts, embargotest.WithLimits(128, time.Minute))
	case "timeout":
		opts = append(opts, embargotest.WithLimits(1<<20, 100*time.Millisecond))
	}
	os.Exit(embargotest.Guard(m, opts...))
}

func TestPackageOutput(t *testing.T) {
	t.Parallel()
	// #nosec G101 -- Public fake canary used only to assert leak detection.
	secret := "embargo-fake-secret-0123456789ab"
	switch os.Getenv("GUARD_CASE") {
	case "overflow":
		t.Log(strings.Repeat("x", 1024))
	case "timeout":
		time.Sleep(10 * time.Second)
	case "subtest":
		t.Run("leaking_child", func(t *testing.T) { t.Log(secret) })
	case "stdout":
		if _, err := fmt.Fprintln(os.Stdout, secret); err != nil {
			t.Fatal(err)
		}
	case "stderr":
		if _, err := fmt.Fprintln(os.Stderr, secret); err != nil {
			t.Fatal(err)
		}
	case "slog":
		slog.Info("forgotten", slog.String("data", secret))
	case "tlog":
		t.Log(secret)
	case "detector":
		t.Log("password=forgotten")
	case "panic":
		panic(secret)
	case "subprocess":
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		// #nosec G204 -- Current test executable and fixed helper name, without a shell.
		cmd := exec.CommandContext(t.Context(), exe, "-test.run=^TestInheritedChild$")
		cmd.Env = append(os.Environ(), "GUARD_INHERITED=1")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
	default:
		t.Log("safe output")
	}
}
func TestParallelPeer(t *testing.T) { t.Parallel(); t.Log("parallel output") }
func TestInheritedChild(t *testing.T) {
	t.Parallel()
	if os.Getenv("GUARD_INHERITED") == "1" {
		if _, err := fmt.Fprintln(os.Stdout, "password=inherited-secret"); err != nil {
			t.Fatal(err)
		}
	}
}
