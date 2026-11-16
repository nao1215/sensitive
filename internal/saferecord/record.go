package saferecord

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"
)

// SanitizationError identifies a sanitization failure without carrying input or panic data.
type SanitizationError uint8

const (
	// ErrMasking covers invalid encodings, unsupported values and scanner panics.
	ErrMasking SanitizationError = iota
	// ErrSizeLimit covers byte, scan and nesting limits.
	ErrSizeLimit
	// ErrCanceled covers cancellation and exhausted masking deadlines.
	ErrCanceled
)

// Error keeps the public JSON error text independent of its cause.
func (SanitizationError) Error() string { return "embargo: invalid or unmaskable JSON" }

// Reason classifies only trusted errors and never reads an error's text.
func Reason(ctx context.Context, err error) SanitizationError {
	if ctx.Err() != nil {
		return ErrCanceled
	}
	if failure, ok := errors.AsType[SanitizationError](err); ok {
		return failure
	}
	return ErrMasking
}

// Message selects a fixed diagnostic without formatting original values.
func Message(reason SanitizationError) string {
	switch reason {
	case ErrSizeLimit:
		return "embargo: record withheld (size limit)"
	case ErrCanceled:
		return "embargo: record withheld (canceled)"
	case ErrMasking:
		return "embargo: record withheld (masking error)"
	default:
		return "embargo: record withheld (masking error)"
	}
}

// Budget detaches request cancellation while bounding subsequent cooperative work.
// Values survive; a running user callback or downstream sink cannot be interrupted.
func Budget(ctx context.Context) (context.Context, context.CancelFunc) {
	const timeout = 100 * time.Millisecond
	return context.WithTimeout(context.WithoutCancel(ctx), timeout)
}

// Slog replaces every attribute and source location, preserving time and level.
func Slog(ctx context.Context, next slog.Handler, when time.Time, level slog.Level, count int, reason SanitizationError) error {
	detached, cancel := Budget(ctx)
	defer cancel()
	record := slog.NewRecord(when, level, Message(reason), 0)
	record.AddAttrs(slog.Int("withheld_attributes", count))
	return next.Handle(detached, record)
}

// JSON provides the standard field names used by formatter fallbacks.
// It accepts only a trusted level spelling; arbitrary severity text is omitted.
func JSON(when time.Time, level string, count int, reason SanitizationError) []byte {
	var out []byte
	out = append(out, `{"time":`...)
	out = strconv.AppendQuote(out, when.Format(time.RFC3339Nano))
	out = append(out, ` ,"level":`...)
	switch level {
	case "trace", "debug", "info", "warn", "warning", "error", "dpanic", "panic", "fatal":
	default:
		level = ""
	}
	out = strconv.AppendQuote(out, level)
	out = append(out, `,"msg":"`...)
	out = append(out, Message(reason)...)
	out = append(out, `","withheld_attributes":`...)
	const decimalBase = 10
	out = strconv.AppendInt(out, int64(count), decimalBase)
	return append(out, '}', '\n')
}
