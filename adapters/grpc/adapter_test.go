package embargogrpc_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"

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
	result, err := unary(t.Context(), nil, &grpc.UnaryServerInfo{FullMethod: "/failure/Unary"}, func(context.Context, any) (any, error) { return "response", original })
	if result != "response" || !errors.Is(err, original) || output.Len() != 0 {
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
	if err != nil || output.Len() != 0 {
		t.Fatal("oversized metadata was logged or changed the RPC result")
	}
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
