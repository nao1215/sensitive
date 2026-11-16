package embargogrpc_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/nao1215/embargo"
	embargogrpc "github.com/nao1215/embargo/adapters/grpc"
)

func ExampleNewUnaryServerInterceptor() {
	var logs bytes.Buffer
	interceptor := embargogrpc.NewUnaryServerInterceptor(slog.New(slog.NewTextHandler(&logs, nil)), embargo.NewScanner())
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer opaque-session"))
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/checkout.Payments/Create"}, func(context.Context, any) (any, error) {
		return nil, status.Error(codes.PermissionDenied, "password=opaque-password")
	})
	fmt.Println(status.Code(err))
	fmt.Println(strings.Contains(logs.String(), "opaque-session"), strings.Contains(logs.String(), "opaque-password"))
	// Output:
	// PermissionDenied
	// false false
}

type exampleStream struct {
	grpc.ServerStream
}

func (*exampleStream) Context() context.Context { return context.Background() }

func ExampleNewStreamServerInterceptor() {
	var logs bytes.Buffer
	interceptor := embargogrpc.NewStreamServerInterceptor(slog.New(slog.NewTextHandler(&logs, nil)), embargo.NewScanner())
	err := interceptor(nil, &exampleStream{}, &grpc.StreamServerInfo{FullMethod: "/checkout.Payments/Watch"}, func(any, grpc.ServerStream) error {
		return status.Error(codes.Unavailable, "alice@example.com disconnected")
	})
	fmt.Println(status.Code(err), strings.Contains(logs.String(), "alice@example.com"))
	// Output: Unavailable false
}
