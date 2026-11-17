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
	"strings"
	"testing"
	texttemplate "text/template"
)

const (
	valueSlogText = "slog/text"
	valueSlogJSON = "slog/json"
)

// CheckValue exercises a constructed canary value through fmt, JSON, XML, TextMarshaler, templates, slog and wrapped errors. Reports identify the leaking path without printing the value.
//
// Direct fmt checks use %v, %+v, %#v, %s, %q and %x; an unexported-field check uses the three v forms, where fmt bypasses output methods. Missing TextMarshaler, serializer errors and panics fail because an unsupported path provides no evidence of safe output.
//
// Diagnostic output containing %! or !ERROR: and slog groups deeper than 64 fail conservatively. Constructors must terminate. Use this for an application-owned password type, Secret or initialized Input; it checks formatting, not Reveal or memory secrecy.
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
	for _, path := range []string{"fmt/%v", "fmt/%+v", "fmt/%#v", "fmt/%s", "fmt/%q", "fmt/%x", "fmt/unexported/%v", "fmt/unexported/%+v", "fmt/unexported/%#v", "json", "xml", "text", "text/template", "html/template", valueSlogText, valueSlogJSON, "error/%v", "error/%w"} {
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
	if format, nested := strings.CutPrefix(path, "fmt/unexported/"); nested {
		data = []byte(fmt.Sprintf(format, struct{ value any }{value: value}))
		return data, !bytes.Contains(data, []byte("%!"))
	}
	data, supported, err := renderValue(path, value)
	if !supported {
		return nil, false
	}
	// fmt recovers formatter panics internally and emits a diagnostic instead.
	// Such output is not a successful implementation of the formatting contract.
	return data, err == nil && !bytes.Contains(data, []byte("%!")) && !bytes.Contains(data, []byte("!ERROR:"))
}

// renderValue writes value through the named output path. supported is false
// for an unknown path or a value without the TextMarshaler the path requires.
func renderValue(path string, value any) (data []byte, supported bool, err error) {
	var buf bytes.Buffer
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
			return nil, false, nil
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
		return nil, false, nil
	}
	return data, true, err
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
