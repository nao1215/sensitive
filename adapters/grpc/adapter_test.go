package embargogrpc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/nao1215/embargo"
	embargogrpc "github.com/nao1215/embargo/adapters/grpc"
)

const grpcResponse = "response"

type healthServer struct {
	grpc_health_v1.UnimplementedHealthServer
}

func (*healthServer) Check(ctx context.Context, _ *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	values, _ := metadata.FromIncomingContext(ctx)
	if values.Get("authorization")[0] != "Bearer private-session" {
		return nil, status.Error(codes.Internal, "metadata changed")
	}
	return nil, status.Error(codes.PermissionDenied, "password=synthetic-unary-password")
}

func (*healthServer) Watch(_ *grpc_health_v1.HealthCheckRequest, _ grpc.ServerStreamingServer[grpc_health_v1.HealthCheckResponse]) error {
	return status.Error(codes.ResourceExhausted, "email=stream@example.com")
}

func TestInterceptorsWithRealGRPC(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	scanner := embargo.NewScanner()
	server := grpc.NewServer(grpc.UnaryInterceptor(embargogrpc.NewUnaryServerInterceptor(logger, scanner)), grpc.StreamInterceptor(embargogrpc.NewStreamServerInterceptor(logger, scanner)))
	grpc_health_v1.RegisterHealthServer(server, &healthServer{})
	listener := bufconn.Listen(1 << 20)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	connection, err := grpc.NewClient("passthrough:///memory", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := connection.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	client := grpc_health_v1.NewHealthClient(connection)
	ctx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer private-session", "public", "kept"))
	_, err = client.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "synthetic-unary-password") {
		t.Fatalf("RPC error changed: %v", err)
	}
	stream, err := client.Watch(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatal(err)
	}
	text := output.String()
	for _, secret := range []string{"private-session", "synthetic-unary-password", "stream@example.com"} {
		if strings.Contains(text, secret) {
			t.Errorf("log leaked %s", secret)
		}
	}
	if strings.Count(text, "grpc request") != 2 || !strings.Contains(text, "kept") {
		t.Fatal(text)
	}
}

type failingRPCError struct{}

func (*failingRPCError) Error() string { panic("private error formatter panic") }

func TestLogFormattingFailurePreservesRPCResult(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	original := &failingRPCError{}
	unary := embargogrpc.NewUnaryServerInterceptor(logger, embargo.NewScanner())
	result, err := unary(t.Context(), nil, &grpc.UnaryServerInfo{FullMethod: "/failure/Unary"}, func(context.Context, any) (any, error) { return grpcResponse, original })
	if result != grpcResponse || !errors.Is(err, original) || output.Len() != 0 {
		t.Fatal("failed log changed the unary response")
	}
	stream := embargogrpc.NewStreamServerInterceptor(logger, embargo.NewScanner())
	if err := stream(nil, &exampleStream{}, &grpc.StreamServerInfo{FullMethod: "/failure/Stream"}, func(any, grpc.ServerStream) error { return original }); !errors.Is(err, original) || output.Len() != 0 {
		t.Fatal("failed log changed the stream result")
	}
}

func TestOversizedMetadataSuppressesAccessRecord(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	interceptor := embargogrpc.NewUnaryServerInterceptor(logger, embargo.NewScanner())
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("public", strings.Repeat("x", 1<<20)))
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/limit/Unary"}, func(context.Context, any) (any, error) { return "accepted metadata", nil })
	if err != nil {
		t.Fatal("logging changed the RPC result")
	}
	requireSuppressedOrDiagnostic(t, output.Bytes(), "size limit")
}

func TestContextErrorsUseWireStatusInAccessRecords(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		err  error
		code codes.Code
	}{
		{context.Canceled, codes.Canceled},
		{context.DeadlineExceeded, codes.DeadlineExceeded},
		{fmt.Errorf("wrapped: %w", context.Canceled), codes.Canceled},
		{fmt.Errorf("wrapped: %w", context.DeadlineExceeded), codes.DeadlineExceeded},
		{status.Error(codes.Unknown, "context canceled"), codes.Unknown},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&output, nil))
			unary := embargogrpc.NewUnaryServerInterceptor(logger, embargo.NewScanner())
			result, err := unary(t.Context(), nil, &grpc.UnaryServerInfo{FullMethod: "/context/Unary"}, func(context.Context, any) (any, error) { return "kept", tc.err })
			if result != "kept" || !errors.Is(err, tc.err) {
				t.Fatal("unary result changed")
			}
			stream := embargogrpc.NewStreamServerInterceptor(logger, embargo.NewScanner())
			if err := stream(nil, &exampleStream{}, &grpc.StreamServerInfo{FullMethod: "/context/Stream"}, func(any, grpc.ServerStream) error { return tc.err }); !errors.Is(err, tc.err) {
				t.Fatal("stream error changed")
			}
			if strings.Count(output.String(), `"code":"`+tc.code.String()+`"`) != 2 {
				t.Fatal(output.String())
			}
		})
	}
}

func TestMetadataOriginalKeyContext(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("cvv", "731", "client_secret", "opaque-client-value", "expiry", "12/29"))
	interceptor := embargogrpc.NewUnaryServerInterceptor(slog.New(slog.NewJSONHandler(&out, nil)), embargo.NewScanner())
	response, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/checkout/Pay"}, func(context.Context, any) (any, error) { return "ok", nil })
	if err != nil || response != "ok" {
		t.Fatal("service changed")
	}
	for _, value := range []string{"731", "opaque-client-value", "12/29"} {
		if strings.Contains(out.String(), `"`+value+`"`) {
			t.Fatalf("metadata leaked: %s", out.String())
		}
	}
	if strings.Count(out.String(), "[REDACTED]") != 3 {
		t.Fatal(out.String())
	}
}

type cancelingScan struct {
	cancel context.CancelFunc
	calls  int
}

func (d *cancelingScan) Scan([]byte) []embargo.Finding { d.calls++; d.cancel(); return nil }

func TestGRPCContextCancellation(t *testing.T) {
	t.Parallel()
	for _, streaming := range []bool{false, true} {
		for _, alreadyCanceled := range []bool{true, false} {
			t.Run(strconv.FormatBool(streaming)+"/"+strconv.FormatBool(alreadyCanceled), func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if alreadyCanceled {
					cancel()
				}
				detector := &cancelingScan{cancel: cancel}
				scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(detector))
				var out bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&out, nil))
				response := any(grpcResponse)
				var err error
				if streaming {
					hook := embargogrpc.NewStreamServerInterceptor(logger, scanner)
					err = hook(nil, &contextStream{getContext: func() context.Context { return ctx }}, &grpc.StreamServerInfo{FullMethod: "/test/Stream"}, func(any, grpc.ServerStream) error { return nil })
				} else {
					hook := embargogrpc.NewUnaryServerInterceptor(logger, scanner)
					response, err = hook(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, func(context.Context, any) (any, error) { return grpcResponse, nil })
				}
				want := 1
				if alreadyCanceled {
					want = 0
				}
				if response != grpcResponse || err != nil || detector.calls != want {
					t.Fatalf("err=%v bytes=%d scans=%d want=%d", err, out.Len(), detector.calls, want)
				}
				if alreadyCanceled && out.Len() != 0 {
					t.Fatal("already canceled request reached logger")
				}
				requireSuppressedOrDiagnostic(t, out.Bytes(), "canceled")
			})
		}
	}
}

type contextStream struct {
	grpc.ServerStream

	getContext func() context.Context
}

func (s *contextStream) Context() context.Context { return s.getContext() }

func TestMetadataMaskedKeyCollision(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("a@example.com", "4111111111111111", "z@example.com", "retained"))
	hook := embargogrpc.NewUnaryServerInterceptor(slog.New(slog.NewJSONHandler(&out, nil)), embargo.NewScanner())
	if _, err := hook(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/collision/Method"}, func(context.Context, any) (any, error) { return grpcResponse, nil }); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "4111111111111111") || !strings.Contains(out.String(), "retained") {
		t.Fatal(out.String())
	}
}

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

// Root handler versions differ in failure reporting; neither may forward input.
func requireSuppressedOrDiagnostic(t *testing.T, data []byte, reason string) {
	t.Helper()
	if len(data) == 0 {
		return
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if len(record) != 4 || record["level"] != "INFO" || record["msg"] != "embargo: record withheld ("+reason+")" || record["withheld_attributes"] != float64(4) {
		t.Fatal("failed access record retained original content")
	}
	stamp, ok := record["time"].(string)
	if !ok {
		t.Fatal("diagnostic lost its timestamp")
	}
	if _, err := time.Parse(time.RFC3339Nano, stamp); err != nil {
		t.Fatal(err)
	}
}
