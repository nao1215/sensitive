// Package domain demonstrates a secret type that imports only the standard library.
package domain

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
)

// Password keeps credential storage behind an unexported pointer.
type Password struct{ value *string }

// NewPassword keeps fmt from expanding the raw string inside an unexported field.
func NewPassword(value string) Password { return Password{value: &value} }

// String supplies the display marker to fmt and templates.
func (Password) String() string { return "[REDACTED]" }

// GoString also hides the value in Go-syntax output.
func (Password) GoString() string { return "[REDACTED]" }

// Format ignores the requested representation and writes the marker.
func (Password) Format(state fmt.State, _ rune) {
	if _, err := io.WriteString(state, "[REDACTED]"); err != nil {
		return
	}
}

// LogValue gives slog a plain redacted string.
func (Password) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON stores a JSON marker string; this encoding cannot restore the password.
func (Password) MarshalJSON() ([]byte, error) { return json.Marshal("[REDACTED]") }

// MarshalText writes the marker in text encoders and JSON map keys.
func (Password) MarshalText() ([]byte, error) { return []byte("[REDACTED]"), nil }

// MarshalXML emits a marker inside the requested XML element.
func (Password) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement("[REDACTED]", start)
}
