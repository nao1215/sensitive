package embargogrpc

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/output"
	"github.com/nao1215/embargo/internal/saferecord"
)

// NewUnaryServerInterceptor records incoming metadata and the final unary error through a masking handler.
// Both arguments are required. Access logging uses context.WithoutCancel plus a
// 100 ms timeout, preserving masked logs after request cancellation. Failures
// emit time, level, a fixed reason and withheld_attributes without original fields.
// Running callbacks cannot be interrupted. RPC responses and errors are unchanged.
func NewUnaryServerInterceptor(logger *slog.Logger, scanner *embargo.Scanner) grpc.UnaryServerInterceptor {
	output.Require(logger)
	output.Require(scanner)
	safe := embargo.NewSlogHandler(logger.Handler(), scanner)
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		response, err := handler(ctx, request)
		record(ctx, logger.Handler(), safe, info.FullMethod, err)
		return response, err
	}
}

// NewStreamServerInterceptor emits one access record when a stream handler returns.
// The record includes incoming metadata and masked error text, without buffering
// stream messages. It uses the unary hook's detached 100 ms budget and diagnostic
// fallback, retaining access records for canceled streams.
func NewStreamServerInterceptor(logger *slog.Logger, scanner *embargo.Scanner) grpc.StreamServerInterceptor {
	output.Require(logger)
	output.Require(scanner)
	safe := embargo.NewSlogHandler(logger.Handler(), scanner)
	return func(service any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		err := handler(service, stream)
		record(stream.Context(), logger.Handler(), safe, info.FullMethod, err)
		return err
	}
}

func record(ctx context.Context, next, safe slog.Handler, method string, err error) {
	ctx, cancel := saferecord.Budget(ctx)
	defer cancel()
	const attributeCount = 4
	when := time.Now()
	complete := false
	defer func() {
		_ = recover() //nolint:errcheck // A formatter panic must not replace the service result.
		if !complete {
			if sinkErr := saferecord.Slog(ctx, next, when, slog.LevelInfo, attributeCount, saferecord.Reason(ctx, nil)); sinkErr != nil {
				return
			}
		}
	}()
	if !safe.Enabled(ctx, slog.LevelInfo) {
		complete = true
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
	record := slog.NewRecord(when, slog.LevelInfo, "grpc request", 0)
	record.AddAttrs(slog.String("method", method), slog.Any("metadata", values), slog.String("code", code.Code().String()), slog.String("error", message))
	complete = true
	if err := safe.Handle(ctx, record); err != nil {
		return
	}
}
