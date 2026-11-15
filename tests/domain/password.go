// Package domain demonstrates a secret type that imports only the standard library.
package domain

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
)

// Password is an application-owned credential with explicit output behavior.
type Password string

// String protects ordinary string formatting and templates.
func (Password) String() string { return "[REDACTED]" }

// GoString protects Go-syntax formatting.
func (Password) GoString() string { return "[REDACTED]" }

// Format protects every fmt verb, including quotes and hexadecimal.
func (Password) Format(state fmt.State, _ rune) {
	if _, err := io.WriteString(state, "[REDACTED]"); err != nil {
		return
	}
}

// LogValue protects a direct slog attribute.
func (Password) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON protects JSON leaves, including nested structured logger values.
func (Password) MarshalJSON() ([]byte, error) { return json.Marshal("[REDACTED]") }

// MarshalText protects text encoding; JSON bypasses it for string-typed map keys.
func (Password) MarshalText() ([]byte, error) { return []byte("[REDACTED]"), nil }

// MarshalXML protects XML element content.
func (Password) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement("[REDACTED]", start)
}
