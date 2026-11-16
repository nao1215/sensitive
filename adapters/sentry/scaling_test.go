package embargosentry_test

import (
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/getsentry/sentry-go"

	"github.com/nao1215/embargo"
	embargosentry "github.com/nao1215/embargo/adapters/sentry"
)

func sentryScalingCall(size int) func() {
	hook := embargosentry.NewBeforeSend(embargo.NewScanner(embargo.WithAll()))
	event := sentry.NewEvent()
	event.Message = strings.Repeat("x", size)
	return func() { hook(event, nil) }
}

//nolint:paralleltest // Measure the delta without concurrent allocations from other tests.
func TestHookAllocationBudget(t *testing.T) {
	const size = 64 << 10
	call := sentryScalingCall(size)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	call()
	runtime.ReadMemStats(&after)
	if after.TotalAlloc-before.TotalAlloc > 128*size+1<<20 {
		t.Fatal("Sentry hook allocation amplification")
	}
}

func BenchmarkHookScaling(b *testing.B) {
	for _, size := range []int{1 << 10, 16 << 10, 256 << 10, 1 << 20, 16 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			call := sentryScalingCall(size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				call()
			}
		})
	}
}
