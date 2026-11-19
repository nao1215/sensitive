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
	"slices"
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
	"github.com/nao1215/embargo/internal/saferecord"
)

const (
	publicMethod   = "/public/Method"
	grpcResponse   = "response"
	grpcMessage    = "grpc request"
	redacted       = "[REDACTED]"
	canceledReason = "canceled"
)

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
	if strings.Count(text, grpcMessage) != 2 || !strings.Contains(text, "kept") {
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
	if result != grpcResponse || !errors.Is(err, original) || !strings.Contains(output.String(), "record withheld") {
		t.Fatal("failed log changed the unary response")
	}
	requireDiagnostic(t, output.Bytes(), "masking error")
	output.Reset()
	stream := embargogrpc.NewStreamServerInterceptor(logger, embargo.NewScanner())
	if err := stream(nil, &exampleStream{}, &grpc.StreamServerInfo{FullMethod: "/failure/Stream"}, func(any, grpc.ServerStream) error { return original }); !errors.Is(err, original) || !strings.Contains(output.String(), "record withheld") {
		t.Fatal("failed log changed the stream result")
	}
	requireDiagnostic(t, output.Bytes(), "masking error")
}

//nolint:paralleltest // Isolate reason checks under the real 100 ms masking budget.
func TestOversizedMetadataEmitsDiagnostic(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	interceptor := embargogrpc.NewUnaryServerInterceptor(logger, embargo.NewScanner())
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("public", strings.Repeat("x", 1<<20)))
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/limit/Unary"}, func(context.Context, any) (any, error) { return "accepted metadata", nil })
	if err != nil {
		t.Fatal("logging changed the RPC result")
	}
	requireDiagnostic(t, output.Bytes(), "size limit")
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
				scanner := embargo.NewScanner(embargo.WithDetector(detector))
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "planted-secret", "email", "alice@example.com"))
				var out bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&out, nil))
				response := any(grpcResponse)
				var err error
				if streaming {
					hook := embargogrpc.NewStreamServerInterceptor(logger, scanner)
					err = hook(nil, &contextStream{getContext: func() context.Context { return ctx }}, &grpc.StreamServerInfo{FullMethod: "/test/alice@example.com"}, func(any, grpc.ServerStream) error {
						cancel()
						return status.Error(codes.ResourceExhausted, "alice@example.com")
					})
				} else {
					hook := embargogrpc.NewUnaryServerInterceptor(logger, scanner)
					response, err = hook(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/alice@example.com"}, func(context.Context, any) (any, error) {
						cancel()
						return grpcResponse, status.Error(codes.ResourceExhausted, "alice@example.com")
					})
				}
				if response != grpcResponse || status.Code(err) != codes.ResourceExhausted || !strings.Contains(out.String(), grpcMessage) || detector.calls == 0 {
					t.Fatalf("err=%v output=%s scans=%d", err, out.String(), detector.calls)
				}
				requireCanceledAccessRecord(t, out.Bytes())
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
		if _, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/scaling/Call"}, func(context.Context, any) (any, error) { return grpcResponse, nil }); err != nil {
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

type auditPanicDetector struct{}

func (auditPanicDetector) Scan([]byte) []embargo.Finding { panic("planted-panic") }

func TestWithheldRecord(t *testing.T) {
	t.Parallel()
	for _, streaming := range []bool{false, true} {
		for _, reason := range []string{"masking error", "size limit", canceledReason} {
			t.Run(fmt.Sprintf("stream=%v/%s", streaming, reason), func(t *testing.T) {
				t.Parallel()
				testWithheldRPC(t, streaming, reason)
			})
		}
	}
}

type budgetDetector struct {
	cancel context.CancelFunc
	calls  int
}

func (d *budgetDetector) Scan([]byte) []embargo.Finding {
	d.calls++
	if d.cancel != nil {
		d.cancel()
	}
	return nil
}

func TestMaskingBudgetEmitsFallback(t *testing.T) {
	t.Parallel()
	for _, streaming := range []bool{false, true} {
		t.Run(strconv.FormatBool(streaming), func(t *testing.T) {
			t.Parallel()
			detector := &budgetDetector{}
			ticks := 0
			ctx := saferecord.WithAccessPolicy(t.Context(), saferecord.AccessPolicy{
				Now: func() time.Time { ticks++; return time.Unix(7, 0).Add(time.Duration(ticks) * time.Second) },
				Timeout: func(parent context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
					if budget != 100*time.Millisecond || parent.Err() != nil {
						t.Error("wrong detached budget")
					}
					bounded, cancel := context.WithCancel(parent)
					detector.cancel = cancel
					return bounded, cancel
				},
			})
			ctx, cancel := context.WithCancel(ctx)
			cancel()
			scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(detector))
			var out bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&out, nil))
			serviceError := status.Error(codes.ResourceExhausted, "planted-error")
			var err error
			if streaming {
				err = embargogrpc.NewStreamServerInterceptor(logger, scanner)(nil, &contextStream{getContext: func() context.Context { return ctx }}, &grpc.StreamServerInfo{FullMethod: "planted-method"}, func(any, grpc.ServerStream) error { return serviceError })
			} else {
				_, err = embargogrpc.NewUnaryServerInterceptor(logger, scanner)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "planted-method"}, func(context.Context, any) (any, error) { return grpcResponse, serviceError })
			}
			if !errors.Is(err, serviceError) || detector.calls != 1 {
				t.Fatalf("err=%v scans=%d", err, detector.calls)
			}
			requireDiagnostic(t, out.Bytes(), canceledReason)
			var record map[string]any
			if err := json.Unmarshal(out.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if record["code"] != codes.ResourceExhausted.String() || record["duration"] != float64(time.Second) || strings.Contains(out.String(), "planted") {
				t.Fatalf("outcome lost or input survived: %s", out.String())
			}
		})
	}
}

func TestOrdinaryRequestUsesOriginalContext(t *testing.T) {
	t.Parallel()
	ctx := saferecord.WithAccessPolicy(t.Context(), saferecord.AccessPolicy{Timeout: func(context.Context, time.Duration) (context.Context, context.CancelFunc) {
		t.Fatal("ordinary request got detached budget")
		return nil, nil
	}})
	var out bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&out, nil))
	if _, err := embargogrpc.NewUnaryServerInterceptor(logger, embargo.NewScanner())(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/audit/Unary"}, func(context.Context, any) (any, error) { return grpcResponse, nil }); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["msg"] != grpcMessage || record["code"] != codes.OK.String() || record["duration"] == nil {
		t.Fatalf("ordinary access record missing: %s", out.String())
	}
}

func testWithheldRPC(t *testing.T, streaming bool, reason string) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	scanner := embargo.NewScanner()
	value := "planted-value"
	if reason == "masking error" {
		scanner = embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(auditPanicDetector{}))
	}
	if reason == "size limit" {
		value += strings.Repeat("x", 1<<20)
	}
	if reason == canceledReason {
		cancel()
	}
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "planted-secret", "public", value))
	var out bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&out, nil))
	var err error
	if streaming {
		err = embargogrpc.NewStreamServerInterceptor(logger, scanner)(nil, &contextStream{getContext: func() context.Context { return ctx }}, &grpc.StreamServerInfo{FullMethod: "/audit/Stream"}, func(any, grpc.ServerStream) error { return nil })
	} else {
		_, err = embargogrpc.NewUnaryServerInterceptor(logger, scanner)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/audit/Unary"}, func(context.Context, any) (any, error) { return grpcResponse, nil })
	}
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("missing access record: %v", err)
	}
	if reason != canceledReason {
		requireDiagnostic(t, out.Bytes(), reason)
	}
	if reason == canceledReason {
		values, ok := got["metadata"].(map[string]any)
		if !ok || values["authorization"] != redacted || got["msg"] != grpcMessage || got["code"] != codes.OK.String() || got["duration"] == nil || strings.Contains(out.String(), "planted-secret") {
			t.Fatal(out.String())
		}
	} else if got["code"] != codes.OK.String() || got["duration"] == nil || got["msg"] != "embargo: record withheld ("+reason+")" || got["withheld_attributes"] != float64(3) || strings.Contains(out.String(), "planted") {
		t.Fatal(out.String())
	}
}

// Diagnostic records contain only fixed metadata and trusted protocol outcomes.
func requireDiagnostic(t *testing.T, data []byte, reason string) {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if len(record) != 6 || record["level"] != "INFO" || record["msg"] != "embargo: record withheld ("+reason+")" || record["withheld_attributes"] != float64(3) {
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

func requireCanceledAccessRecord(t *testing.T, data []byte) {
	t.Helper()
	var record map[string]any
	if decodeErr := json.Unmarshal(data, &record); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	values, ok := record["metadata"].(map[string]any)
	if !ok || record["msg"] != grpcMessage || record["method"] != "/test/[REDACTED]" || record["code"] != codes.ResourceExhausted.String() || values["authorization"] != redacted || record["error"] != "rpc error: code = ResourceExhausted desc = [REDACTED]" {
		t.Fatalf("wrong access record: %s", string(data))
	}
	email, ok := values["email"].([]any)
	if !ok || len(email) != 1 || email[0] != redacted {
		t.Fatalf("metadata not masked: %s", string(data))
	}
}

func TestWithheldOutcomeSchemaProperty(t *testing.T) {
	t.Parallel()
	for code := codes.OK; code <= codes.Unauthenticated; code++ {
		for _, streaming := range []bool{false, true} {
			var out bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&out, nil))
			scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(auditPanicDetector{}))
			ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("planted-key", "private@example.com"))
			serviceError := status.Error(code, "private@example.com")
			var err error
			if streaming {
				err = embargogrpc.NewStreamServerInterceptor(logger, scanner)(nil, &contextStream{getContext: func() context.Context { return ctx }}, &grpc.StreamServerInfo{FullMethod: "/planted/Method"}, func(any, grpc.ServerStream) error { return serviceError })
			} else {
				_, err = embargogrpc.NewUnaryServerInterceptor(logger, scanner)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/planted/Method"}, func(context.Context, any) (any, error) { return grpcResponse, serviceError })
			}
			if !errors.Is(err, serviceError) {
				t.Fatal("service outcome changed")
			}
			requireDiagnostic(t, out.Bytes(), "masking error")
			var record map[string]any
			if err := json.Unmarshal(out.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if record["code"] != code.String() || record["duration"] == nil || strings.Contains(out.String(), "planted") || strings.Contains(out.String(), "private@example.com") {
				t.Fatal("withheld record lost outcome or retained input")
			}
		}
	}
}

func TestNumericMetadataLexemeProperty(t *testing.T) {
	t.Parallel()
	const integer = "4111111111111111"
	for position := 1; position < len(integer); position++ {
		for _, sign := range []string{"", "-"} {
			lexeme := sign + integer[:position] + "." + integer[position:] + "00E+00" + strconv.Itoa(len(integer)-position)
			ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("number", lexeme))
			for _, streaming := range []bool{false, true} {
				var out bytes.Buffer
				logger := slog.New(slog.NewJSONHandler(&out, nil))
				if streaming {
					if err := embargogrpc.NewStreamServerInterceptor(logger, embargo.NewScanner())(nil, &contextStream{getContext: func() context.Context { return ctx }}, &grpc.StreamServerInfo{FullMethod: publicMethod}, func(any, grpc.ServerStream) error { return nil }); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := embargogrpc.NewUnaryServerInterceptor(logger, embargo.NewScanner())(ctx, nil, &grpc.UnaryServerInfo{FullMethod: publicMethod}, func(context.Context, any) (any, error) { return grpcResponse, nil }); err != nil {
						t.Fatal(err)
					}
				}
				var record struct {
					Metadata map[string][]string `json:"metadata"`
				}
				if err := json.Unmarshal(out.Bytes(), &record); err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(record.Metadata["number"], []string{redacted}) {
					t.Fatalf("numeric metadata retained part of lexeme %s", lexeme)
				}
			}
		}
	}
}

func TestFreeTextMetadataProperty(t *testing.T) {
	t.Parallel()
	for n := 1; n < 254; n += 17 {
		secret := fmt.Sprintf("opaqueMetadataFixture%dTail", n)
		address := fmt.Sprintf("::ffff:203.0.113.%d", n)
		for _, text := range []string{fmt.Sprintf("map[Authorization:[Bearer %s]]", secret), fmt.Sprintf("body=%q", `{"password":"`+secret+`"}`), "password=[REDACTED]" + secret} {
			for _, stream := range []bool{false, true} {
				var out bytes.Buffer
				ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("x-forwarded-for", address, "x-context", text))
				logger := slog.New(slog.NewJSONHandler(&out, nil))
				scanner := embargo.NewScanner()
				serviceError := errors.New(text)
				var err error
				if stream {
					err = embargogrpc.NewStreamServerInterceptor(logger, scanner)(nil, &contextStream{getContext: func() context.Context { return ctx }}, &grpc.StreamServerInfo{FullMethod: publicMethod}, func(any, grpc.ServerStream) error { return serviceError })
				} else {
					_, err = embargogrpc.NewUnaryServerInterceptor(logger, scanner)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: publicMethod}, func(context.Context, any) (any, error) { return grpcResponse, serviceError })
				}
				if !errors.Is(err, serviceError) {
					t.Fatal("RPC outcome changed")
				}
				if out.Len() == 0 || strings.Contains(out.String(), secret) || strings.Contains(out.String(), ".0.113.") || !strings.Contains(out.String(), redacted) {
					t.Fatalf("metadata or error leaked: %s", out.String())
				}
			}
		}
	}
}

func TestMetadataIntegerExpansionFailureIsWithheld(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&out, nil))
	scanner := embargo.NewScanner()
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("email", "alice@example.com", "public", "1e1048576"))
	unary := embargogrpc.NewUnaryServerInterceptor(logger, scanner)
	result, err := unary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: publicMethod}, func(context.Context, any) (any, error) { return grpcResponse, nil })
	if err != nil || result != grpcResponse {
		t.Fatal("masking failure changed the RPC result")
	}
	requireDiagnostic(t, out.Bytes(), "size limit")
	out.Reset()
	stream := embargogrpc.NewStreamServerInterceptor(logger, scanner)
	if err := stream(nil, &contextStream{getContext: func() context.Context { return ctx }}, &grpc.StreamServerInfo{FullMethod: publicMethod}, func(any, grpc.ServerStream) error { return nil }); err != nil {
		t.Fatal(err)
	}
	requireDiagnostic(t, out.Bytes(), "size limit")
}

// panickingHandler panics on every call, as a broken downstream handler can.
type panickingHandler struct{}

func (panickingHandler) Enabled(context.Context, slog.Level) bool  { panic("planted-enabled") }
func (panickingHandler) Handle(context.Context, slog.Record) error { panic("planted-handle") }
func (h panickingHandler) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h panickingHandler) WithGroup(string) slog.Handler           { return h }

func TestPanickingDiagnosticSinkPreservesRPCResult(t *testing.T) {
	t.Parallel()
	original := status.Error(codes.NotFound, "missing")
	unary := embargogrpc.NewUnaryServerInterceptor(slog.New(panickingHandler{}), embargo.NewScanner())
	result, err := unary(t.Context(), nil, &grpc.UnaryServerInfo{FullMethod: publicMethod}, func(context.Context, any) (any, error) { return grpcResponse, original })
	if result != grpcResponse || !errors.Is(err, original) {
		t.Fatal("a panicking sink changed the unary result")
	}
	stream := embargogrpc.NewStreamServerInterceptor(slog.New(panickingHandler{}), embargo.NewScanner())
	if err := stream(nil, &exampleStream{}, &grpc.StreamServerInfo{FullMethod: publicMethod}, func(any, grpc.ServerStream) error { return original }); !errors.Is(err, original) {
		t.Fatal("a panicking sink changed the stream result")
	}
}

func TestDisabledLoggerWritesNothing(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelWarn}))
	unary := embargogrpc.NewUnaryServerInterceptor(logger, embargo.NewScanner())
	result, err := unary(t.Context(), nil, &grpc.UnaryServerInfo{FullMethod: publicMethod}, func(context.Context, any) (any, error) { return grpcResponse, nil })
	if result != grpcResponse || err != nil || output.Len() != 0 {
		t.Fatalf("disabled logger: %v %v %q", result, err, output.String())
	}
}

// failingHandler panics in Enabled and fails the diagnostic write.
type failingHandler struct{ panickingHandler }

func (failingHandler) Handle(context.Context, slog.Record) error { return io.ErrClosedPipe }

func TestFailingDiagnosticSinkPreservesRPCResult(t *testing.T) {
	t.Parallel()
	unary := embargogrpc.NewUnaryServerInterceptor(slog.New(failingHandler{}), embargo.NewScanner())
	result, err := unary(t.Context(), nil, &grpc.UnaryServerInfo{FullMethod: publicMethod}, func(context.Context, any) (any, error) { return grpcResponse, nil })
	if result != grpcResponse || err != nil {
		t.Fatal("a failing sink changed the result")
	}
}
