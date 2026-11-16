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

// Error distinguishes fixed failure reasons without carrying input bytes.
func (e SanitizationError) Error() string {
	switch e {
	case ErrSizeLimit:
		return "embargo: JSON size limit exceeded"
	case ErrCanceled:
		return "embargo: JSON masking canceled"
	case ErrMasking:
		return "embargo: invalid or unmaskable JSON"
	default:
		return "embargo: invalid or unmaskable JSON"
	}
}

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

// Budget detaches only requests already canceled when access logging starts.
// Ordinary requests keep their own context and deadline.
// Values survive; a running user callback or downstream sink cannot be interrupted.
func Budget(ctx context.Context) (context.Context, context.CancelFunc) {
	const timeout = 100 * time.Millisecond
	if ctx.Err() == nil {
		return ctx, func() {}
	}
	policy, ok := ctx.Value(accessPolicyKey{}).(AccessPolicy)
	detached := context.WithoutCancel(ctx)
	if ok && policy.Timeout != nil {
		return policy.Timeout(detached, timeout)
	}
	return context.WithTimeout(detached, timeout)
}

// Slog drops input attributes and source location, preserving time and level.
// Only internal access hooks supply trusted outcome and duration attributes.
func Slog(ctx context.Context, next slog.Handler, when time.Time, level slog.Level, count int, reason SanitizationError, trusted ...slog.Attr) error {
	detached, cancel := Budget(ctx)
	defer cancel()
	record := slog.NewRecord(when, level, Message(reason), 0)
	record.AddAttrs(slog.Int("withheld_attributes", count))
	record.AddAttrs(trusted...)
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

// AccessPolicy is an internal injection seam for deterministic access-log tests.
// Nil functions use the real clock and context.WithTimeout.
type AccessPolicy struct {
	// Now supplies timestamps and duration endpoints.
	Now func() time.Time
	// Timeout creates the cooperative budget for an already canceled request.
	Timeout func(context.Context, time.Duration) (context.Context, context.CancelFunc)
}

type accessPolicyKey struct{}

// WithAccessPolicy scopes an internal clock and timeout factory to a request.
func WithAccessPolicy(ctx context.Context, policy AccessPolicy) context.Context {
	return context.WithValue(ctx, accessPolicyKey{}, policy)
}

// Now reads the request's clock or the real clock when no override was installed.
func Now(ctx context.Context) time.Time {
	policy, ok := ctx.Value(accessPolicyKey{}).(AccessPolicy)
	if ok && policy.Now != nil {
		return policy.Now()
	}
	return time.Now()
}
