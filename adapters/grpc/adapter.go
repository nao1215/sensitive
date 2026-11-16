package embargogrpc

import (
	"context"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/output"
)

// NewUnaryServerInterceptor records incoming metadata and the final unary error through a masking handler.
// Both arguments are required. RPC responses and errors retain their original values for the client.
func NewUnaryServerInterceptor(logger *slog.Logger, scanner *embargo.Scanner) grpc.UnaryServerInterceptor {
	output.Require(logger)
	output.Require(scanner)
	safe := slog.New(embargo.NewSlogHandler(logger.Handler(), scanner))
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		response, err := handler(ctx, request)
		record(ctx, safe, info.FullMethod, err)
		return response, err
	}
}

// NewStreamServerInterceptor emits one access record when a stream handler returns.
// The record includes incoming metadata and masked error text, without buffering stream messages.
func NewStreamServerInterceptor(logger *slog.Logger, scanner *embargo.Scanner) grpc.StreamServerInterceptor {
	output.Require(logger)
	output.Require(scanner)
	safe := slog.New(embargo.NewSlogHandler(logger.Handler(), scanner))
	return func(service any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		err := handler(service, stream)
		record(stream.Context(), safe, info.FullMethod, err)
		return err
	}
}

func record(ctx context.Context, logger *slog.Logger, method string, err error) {
	defer func() {
		_ = recover() //nolint:errcheck // A failed formatter must not replace the service result.
	}()
	if ctx.Err() != nil {
		return
	}
	values, _ := metadata.FromIncomingContext(ctx)
	message := ""
	if err != nil {
		message = err.Error()
	}
	code, ok := status.FromError(err)
	if !ok {
		code = status.FromContextError(err)
	}
	logger.LogAttrs(ctx, slog.LevelInfo, "grpc request", slog.String("method", method), slog.Any("metadata", values), slog.String("code", code.Code().String()), slog.String("error", message))
}
