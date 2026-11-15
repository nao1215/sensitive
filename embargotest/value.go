package embargotest

import (
	"bytes"
	"encoding"
	"encoding/json"
	"encoding/xml"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"testing"
	texttemplate "text/template"
)

// CheckValue constructs a value with a public fake canary and checks its output
// through fmt (%v, %+v, %#v, %s, %q, %x), JSON, XML, TextMarshaler, text/template,
// html/template, both slog handlers and wrapped errors. It reports the exact
// leaking path without printing the value. Missing TextMarshaler, serializer
// errors and panics fail: an unsupported path is not evidence of safe output.
// Constructors must terminate. This verifies formatting, not Reveal or memory
// secrecy. Use it for domain-owned password types, Secret and initialized Input.
func CheckValue(tb testing.TB, construct func(canary string) any) (safe bool) {
	tb.Helper()
	safe = true
	completed := false
	defer func() {
		if !completed {
			_ = recover() //nolint:errcheck // Discard panic contents.
			tb.Error("embargotest: value constructor failed")
			safe = false
		}
	}()
	value := construct(defaultCanary)
	completed = true
	needles := representations([]byte(defaultCanary))
	for _, path := range []string{"fmt/%v", "fmt/%+v", "fmt/%#v", "fmt/%s", "fmt/%q", "fmt/%x", "json", "xml", "text", "text/template", "html/template", "slog/text", "slog/json", "error/%v", "error/%w"} {
		data, ok := formatValue(path, value)
		if !ok {
			tb.Error("embargotest: unsupported or failed value path: " + path)
			safe = false
			continue
		}
		if containsCanary(data, needles) {
			tb.Error("embargotest: value leaked through " + path)
			safe = false
		}
	}
	return safe
}

func formatValue(path string, value any) (data []byte, ok bool) {
	defer func() {
		if !ok {
			_ = recover() //nolint:errcheck // Discard panic contents.
		}
	}()
	var buf bytes.Buffer
	var err error
	switch path {
	case "fmt/%v", "fmt/%+v", "fmt/%#v", "fmt/%s", "fmt/%q", "fmt/%x":
		data = []byte(fmt.Sprintf(path[len("fmt/"):], value))
	case "json":
		data, err = json.Marshal(value)
	case "xml":
		data, err = xml.Marshal(struct {
			Value   any      `xml:"value"`
			XMLName xml.Name `xml:"valuecheck"`
		}{Value: value})
	case "text":
		marshaler, implements := value.(encoding.TextMarshaler)
		if !implements {
			return nil, false
		}
		data, err = marshaler.MarshalText()
	case "text/template":
		err = texttemplate.Must(texttemplate.New("value").Parse("{{.}}")).Execute(&buf, value)
		data = buf.Bytes()
	case "html/template":
		err = htmltemplate.Must(htmltemplate.New("value").Parse("{{.}}")).Execute(&buf, value)
		data = buf.Bytes()
	case "slog/text":
		slog.New(slog.NewTextHandler(&buf, nil)).Info("check", slog.Any("value", value))
		data = buf.Bytes()
	case "slog/json":
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("check", slog.Any("value", value))
		data = buf.Bytes()
	case "error/%v":
		data = []byte(fmt.Errorf("outer: %v", value).Error())
	case "error/%w":
		inner, implements := value.(error)
		if !implements {
			inner = fmt.Errorf("%v", value)
		}
		data = []byte(fmt.Errorf("outer: %w", inner).Error())
	default:
		return nil, false
	}
	return data, err == nil
}
