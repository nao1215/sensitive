package embargo

import (
	"fmt"
	"io"
	"log/slog"
)

// Secret hides a shallow copy of T from supported formatters and serializers.
// Reveal returns that copy; referenced data remains shared with the caller.
// A Secret deliberately does not implement error. Its String method masks a
// direct panic value, but cannot protect revealed values or memory dumps.
type Secret[T any] struct{ value *T }

// NewSecret wraps v without invoking its methods or copying referenced data.
func NewSecret[T any](v T) Secret[T] { return Secret[T]{value: &v} }

// Reveal returns the wrapped value, or T's zero value for a zero Secret.
func (s Secret[T]) Reveal() T {
	if s.value == nil {
		var zero T
		return zero
	}
	return *s.value
}

// String returns the fixed redaction marker.
func (Secret[T]) String() string { return redactionMarker }

// GoString returns the fixed redaction marker.
func (Secret[T]) GoString() string { return redactionMarker }

// Format writes the marker without examining T, regardless of verb or flags.
// The fmt package handles %T and %p itself and may expose types or addresses.
func (Secret[T]) Format(state fmt.State, _ rune) {
	if _, err := io.WriteString(state, redactionMarker); err != nil {
		return
	}
}

// LogValue returns the marker as a slog string.
func (Secret[T]) LogValue() slog.Value { return slog.StringValue(redactionMarker) }

// MarshalJSON returns a JSON string containing the marker.
func (Secret[T]) MarshalJSON() ([]byte, error) { return []byte(`"` + redactionMarker + `"`), nil }

// MarshalText returns the marker as text.
func (Secret[T]) MarshalText() ([]byte, error) { return []byte(redactionMarker), nil }
