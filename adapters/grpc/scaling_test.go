package embargogrpc_test

import (
	"context"
	"io"
	"log/slog"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/nao1215/embargo"
	embargogrpc "github.com/nao1215/embargo/adapters/grpc"
)

func grpcScalingCall(tb testing.TB, size int) func() {
	tb.Helper()
	//nolint:sloglint // Include JSON encoding in this output-path measurement.
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	interceptor := embargogrpc.NewUnaryServerInterceptor(logger, embargo.NewScanner(embargo.WithAll()))
	values := metadata.Pairs("public", strings.Repeat("x", size))
	ctx := metadata.NewIncomingContext(tb.Context(), values)
	streamInterceptor := embargogrpc.NewStreamServerInterceptor(logger, embargo.NewScanner(embargo.WithAll()))
	stream := &scalingStream{values: values}
	return func() {
		if err := streamInterceptor(nil, stream, &grpc.StreamServerInfo{FullMethod: "/scaling/Stream"}, func(any, grpc.ServerStream) error { return nil }); err != nil {
			tb.Fatal(err)
		}
		if _, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/scaling/Call"}, func(context.Context, any) (any, error) { return nil, nil }); err != nil {
			tb.Fatal(err)
		}
	}
}

//nolint:paralleltest // The allocation delta covers one isolated hook call.
func TestHookAllocationBudget(t *testing.T) {
	const size = 64 << 10
	call := grpcScalingCall(t, size)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	call()
	runtime.ReadMemStats(&after)
	if after.TotalAlloc-before.TotalAlloc > 128*size+1<<20 {
		t.Fatal("gRPC hook allocation amplification")
	}
}

func BenchmarkHookScaling(b *testing.B) {
	for _, size := range []int{1 << 10, 16 << 10, 256 << 10, 1 << 20, 16 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			call := grpcScalingCall(b, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				call()
			}
		})
	}
}

type scalingStream struct {
	grpc.ServerStream

	values metadata.MD
}

func (s *scalingStream) Context() context.Context {
	return metadata.NewIncomingContext(context.Background(), s.values)
}
