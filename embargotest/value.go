package embargotest

import (
	"bytes"
	"encoding"
	"encoding/json"
	"encoding/xml"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"slices"
	"testing"
	texttemplate "text/template"
)

const (
	valueSlogText = "slog/text"
	valueSlogJSON = "slog/json"
)

// CheckValue constructs a value with a public fake canary and checks its output
// through fmt (%v, %+v, %#v, %s, %q, %x), JSON, XML, TextMarshaler, text/template,
// html/template, both slog handlers and wrapped errors. It reports the exact
// leaking path without printing the value. Missing TextMarshaler, serializer
// errors and panics fail: an unsupported path is not evidence of safe output.
// Diagnostic output containing %! or !ERROR: and slog groups deeper than 64
// fail conservatively. Constructors must terminate. This verifies formatting, not Reveal or memory
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
	for _, path := range []string{"fmt/%v", "fmt/%+v", "fmt/%#v", "fmt/%s", "fmt/%q", "fmt/%x", "json", "xml", "text", "text/template", "html/template", valueSlogText, valueSlogJSON, "error/%v", "error/%w"} {
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
	if path == valueSlogText || path == valueSlogJSON {
		resolved, valid := resolveCheckValue(slog.AnyValue(value), 0)
		if !valid {
			return nil, false
		}
		value = resolved
	}
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
	case valueSlogText:
		slog.New(slog.NewTextHandler(&buf, nil)).Info("check", slog.Any("value", value))
		data = buf.Bytes()
	case valueSlogJSON:
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
	// fmt recovers formatter panics internally and emits a diagnostic instead.
	// Such output is not a successful implementation of the formatting contract.
	return data, err == nil && !bytes.Contains(data, []byte("%!")) && !bytes.Contains(data, []byte("!ERROR:"))
}

// Freeze nested LogValuers too: handlers resolve group children themselves and
// convert failures to output instead of returning an error to their caller.
func resolveCheckValue(value slog.Value, depth int) (slog.Value, bool) {
	const maxGroupDepth = 64
	if depth >= maxGroupDepth {
		return slog.Value{}, false
	}
	value = value.Resolve()
	if value.Kind() == slog.KindAny {
		_, failed := value.Any().(error)
		return value, !failed
	}
	if value.Kind() == slog.KindGroup {
		attrs := slices.Clone(value.Group())
		for i := range attrs {
			resolved, valid := resolveCheckValue(attrs[i].Value, depth+1)
			if !valid {
				return slog.Value{}, false
			}
			attrs[i].Value = resolved
		}
		value = slog.GroupValue(attrs...)
	}
	return value, true
}
