package embargogrpc_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/nao1215/embargo"
	embargogrpc "github.com/nao1215/embargo/adapters/grpc"
)

func ExampleNewUnaryServerInterceptor() {
	// The time attribute is dropped so the output is reproducible.
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{ReplaceAttr: dropTime}))
	interceptor := embargogrpc.NewUnaryServerInterceptor(logger, embargo.NewScanner())

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer opaque-session"))
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/checkout.Payments/Create"}, func(context.Context, any) (any, error) {
		return nil, status.Error(codes.PermissionDenied, "password=opaque-password")
	})
	fmt.Println(status.Code(err))

	// Output:
	// level=INFO msg="grpc request" method=/checkout.Payments/Create metadata="{\"authorization\":\"[REDACTED]\"}" error="rpc error: code = PermissionDenied desc = password=[REDACTED]" code=PermissionDenied
	// PermissionDenied
}

func dropTime(_ []string, attr slog.Attr) slog.Attr {
	if attr.Key == slog.TimeKey || attr.Key == "duration" {
		return slog.Attr{}
	}
	return attr
}

type exampleStream struct {
	grpc.ServerStream
}

func (*exampleStream) Context() context.Context { return context.Background() }

func ExampleNewStreamServerInterceptor() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{ReplaceAttr: dropTime}))
	interceptor := embargogrpc.NewStreamServerInterceptor(logger, embargo.NewScanner())

	err := interceptor(nil, &exampleStream{}, &grpc.StreamServerInfo{FullMethod: "/checkout.Payments/Watch"}, func(any, grpc.ServerStream) error {
		return status.Error(codes.Unavailable, "alice@example.com disconnected")
	})
	fmt.Println(status.Code(err))

	// Output:
	// level=INFO msg="grpc request" method=/checkout.Payments/Watch metadata="null" error="rpc error: code = Unavailable desc = [REDACTED] disconnected" code=Unavailable
	// Unavailable
}
