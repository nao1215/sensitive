package embargo

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
)

// Input decodes a string or byte slice during initialization. Do not decode or
// display the same Input concurrently. Publish its Secret snapshot afterwards.
// Decode into a fresh DTO: outer JSON syntax errors and absent fields bypass
// these methods. Discard the entire DTO when its decoder fails.
type Input[T interface{ ~string | ~[]byte }] struct{ secret Secret[T] }

type inputError struct{}

func (inputError) Error() string { return "embargo: invalid input" }

// UnmarshalJSON accepts only JSON strings; byte slices use base64 decoding.
// Named types use their underlying representation, never their own decoders.
// Failure, including the redaction marker, clears this Input and returns a
// fixed error. A nil receiver returns the same error.
func (i *Input[T]) UnmarshalJSON(data []byte) error {
	if i == nil {
		return inputError{}
	}
	*i = Input[T]{}
	var text *string
	if err := json.Unmarshal(data, &text); err != nil || text == nil || *text == redactionMarker {
		return inputError{}
	}
	raw := []byte(*text)
	var zero T
	if reflect.TypeOf(zero).Kind() == reflect.Slice {
		decoded, err := base64.StdEncoding.DecodeString(*text)
		if err != nil {
			return inputError{}
		}
		raw = decoded
	}
	return i.UnmarshalText(raw)
}

// UnmarshalText copies raw text without trimming or guessing an encoding.
// The redaction marker is rejected with the same fixed error as JSON failures.
func (i *Input[T]) UnmarshalText(data []byte) error {
	if i == nil {
		return inputError{}
	}
	*i = Input[T]{}
	if string(data) == redactionMarker {
		return inputError{}
	}
	copyOf := append([]byte{}, data...)
	i.secret = NewSecret(T(copyOf))
	return nil
}

// Secret returns the current snapshot; later decoding does not change it.
func (i Input[T]) Secret() Secret[T] { return i.secret }

// String returns the fixed redaction marker.
func (i Input[T]) String() string { return i.secret.String() }

// GoString returns the fixed redaction marker.
func (i Input[T]) GoString() string { return i.secret.GoString() }

// Format writes the marker without examining the input.
func (i Input[T]) Format(state fmt.State, verb rune) { i.secret.Format(state, verb) }

// LogValue returns the marker as a slog string.
func (i Input[T]) LogValue() slog.Value { return i.secret.LogValue() }

// MarshalJSON returns a JSON string containing the marker, never input data.
func (i Input[T]) MarshalJSON() ([]byte, error) { return i.secret.MarshalJSON() }

// MarshalText returns the marker, never input data.
func (i Input[T]) MarshalText() ([]byte, error) { return i.secret.MarshalText() }
