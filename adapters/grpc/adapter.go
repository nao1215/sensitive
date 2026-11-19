package embargogrpc

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/output"
	"github.com/nao1215/embargo/internal/saferecord"
)

// NewUnaryServerInterceptor records incoming metadata and the final unary error through a masking handler.
// Both arguments are required. Access logging uses the request context unless
// already canceled when the record is built; only then it uses WithoutCancel and
// a 100 ms timeout. Failed records retain time, level, code and handler duration,
// a fixed reason and withheld_attributes, without method, metadata or error text.
// Running callbacks cannot be interrupted. RPC responses and errors are unchanged.
func NewUnaryServerInterceptor(logger *slog.Logger, scanner *embargo.Scanner) grpc.UnaryServerInterceptor {
	output.Require(logger)
	output.Require(scanner)
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := saferecord.Now(ctx)
		response, err := handler(ctx, request)
		record(ctx, logger.Handler(), scanner, info.FullMethod, err, start)
		return response, err
	}
}

// NewStreamServerInterceptor emits one access record when a stream handler returns.
// The record includes incoming metadata and masked error text, without buffering
// stream messages. It uses the unary hook's conditional detached budget and
// diagnostic fallback, retaining code and duration even when masking fails.
func NewStreamServerInterceptor(logger *slog.Logger, scanner *embargo.Scanner) grpc.StreamServerInterceptor {
	output.Require(logger)
	output.Require(scanner)
	return func(service any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := saferecord.Now(stream.Context())
		err := handler(service, stream)
		record(stream.Context(), logger.Handler(), scanner, info.FullMethod, err, start)
		return err
	}
}

func record(ctx context.Context, next slog.Handler, scanner *embargo.Scanner, method string, serviceError error, start time.Time) {
	when := saferecord.Now(ctx)
	outcome := &outcomeHandler{Handler: next, code: codes.Unknown, duration: when.Sub(start)}
	ctx, cancel := saferecord.Budget(ctx)
	defer cancel()
	const attributeCount = 3
	complete := false
	defer func() {
		_ = recover() //nolint:errcheck // A formatter panic must not replace the service result.
		if !complete {
			// Nor may a downstream handler that also panics on the diagnostic.
			defer func() { _ = recover() }() //nolint:errcheck // Same reason as above.
			if err := saferecord.Slog(ctx, outcome, when, slog.LevelInfo, attributeCount, saferecord.Reason(ctx, nil)); err != nil {
				return
			}
		}
	}()
	if !next.Enabled(ctx, slog.LevelInfo) {
		complete = true
		return
	}
	result, ok := status.FromError(serviceError)
	if !ok {
		result = status.FromContextError(serviceError)
	}
	if result.Code() <= codes.Unauthenticated {
		outcome.code = result.Code()
	}
	values, _ := metadata.FromIncomingContext(ctx)
	message := ""
	if serviceError != nil {
		message = serviceError.Error()
	}
	access := slog.NewRecord(when, slog.LevelInfo, "grpc request", 0)
	access.AddAttrs(slog.String("method", method), slog.Any("metadata", values), slog.String("error", message))
	safe := embargo.NewSlogHandler(outcome, scanner)
	complete = true
	if err := safe.Handle(ctx, access); err != nil {
		return
	}
}

// outcomeHandler appends only fixed protocol metadata after the masking boundary.
// Both normal and withheld records pass through it exactly once.
type outcomeHandler struct {
	slog.Handler

	duration time.Duration
	code     codes.Code
}

// Handle preserves safe protocol outcomes independently of request sanitization.
//
//nolint:gocritic // slog.Handler requires the record by value.
func (h *outcomeHandler) Handle(ctx context.Context, record slog.Record) error {
	record = record.Clone()
	record.AddAttrs(slog.String("code", h.code.String()), slog.Duration("duration", h.duration))
	return h.Handler.Handle(ctx, record)
}
