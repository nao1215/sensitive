package embargo_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

func httpScalingCall(tb testing.TB, size int) func() {
	tb.Helper()
	//nolint:sloglint // Measure the JSON output boundary even though the bytes are discarded.
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handler := embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), logger, embargo.NewScanner(embargo.WithAll()))
	request := httptest.NewRequestWithContext(tb.Context(), http.MethodGet, "/?public="+strings.Repeat("x", size), http.NoBody)
	return func() { handler.ServeHTTP(httptest.NewRecorder(), request) }
}

//nolint:paralleltest // Allocation accounting must not overlap other tests.
func TestHookAllocationBudget(t *testing.T) {
	const size = 64 << 10
	call := httpScalingCall(t, size)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	call()
	runtime.ReadMemStats(&after)
	if after.TotalAlloc-before.TotalAlloc > 128*size+1<<20 {
		t.Fatal("HTTP hook allocation amplification")
	}
}

func BenchmarkHookScaling(b *testing.B) {
	for _, size := range []int{1 << 10, 16 << 10, 256 << 10, 1 << 20, 16 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			call := httpScalingCall(b, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				call()
			}
		})
	}
}
