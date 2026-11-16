package embargozerolog_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/nao1215/embargo"
	embargozerolog "github.com/nao1215/embargo/adapters/zerolog"
	"github.com/nao1215/embargo/embargotest"
)

type literal struct{ value []byte }

func (d literal) Scan(data []byte) []embargo.Finding {
	var findings []embargo.Finding
	for start := 0; start < len(data); {
		i := bytes.Index(data[start:], d.value)
		if i < 0 {
			break
		}
		start += i
		findings = append(findings, embargo.Finding{Kind: "canary", Start: start, End: start + len(d.value), Confidence: 1})
		start += len(d.value)
	}
	return findings
}

func TestRealLoggerMasksOutput(t *testing.T) {
	t.Parallel()
	canary := "public-fake-canary-0123456789"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN, embargo.KindCVV), embargo.WithDetector(literal{value: []byte(canary)}))
	r := embargotest.New(t, embargotest.WithCanary([]byte(canary)), embargotest.WithScanner(scanner))
	emit(t, r.Writer("logs"), scanner, canary)
	//nolint:goconst // Spell out each field expectation as an independent output contract.
	r.ExpectJSON("logs", nil, map[string]string{"message": "[REDACTED]", "pre": "[REDACTED]", "card": "[REDACTED]", "cvv": "[REDACTED]", "secret": "[REDACTED]"}, 1)
	if !r.Check() {
		t.Fatal("real logger output failed inspection")
	}
}

func emit(t *testing.T, out io.Writer, scanner *embargo.Scanner, canary string) {
	t.Helper()
	sink := embargozerolog.NewWriter(out, scanner)
	logger := zerolog.New(sink).With().Str("pre", canary).Logger()
	logger.Info().Str(canary, "alice@example.com").Int64("card", 4111111111111111).Int("cvv", 123).Interface("secret", embargo.NewSecret(canary)).Interface("nested", map[string]any{"email": "alice@example.com", "values": []string{canary}}).Err(errors.New(canary)).Msg(canary)
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
}

type failedObservation struct {
	testing.TB

	failed bool
}

func (o *failedObservation) Error(...any) { o.failed = true }

func TestEncodedBinaryIsADocumentedLimit(t *testing.T) {
	t.Parallel()
	observation := &failedObservation{TB: t}
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
	r := embargotest.New(observation, embargotest.WithScanner(scanner))
	sink := embargozerolog.NewWriter(r.Writer("logs"), scanner)
	logger := zerolog.New(sink)
	logger.Info().Hex("binary", r.Canary()).Msg("encoded")
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	r.Expect("logs", func(data []byte) bool { return bytes.Contains(data, []byte("encoded")) })
	if r.Check() || !observation.failed {
		t.Fatal("encoded canary must expose the documented runtime detection limit")
	}
}

func TestSensitiveKeyPolicy(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithSensitiveKeys("api_key", "pin"))
	var out bytes.Buffer
	sink := embargozerolog.NewWriter(&out, scanner)
	logger := zerolog.New(sink)
	logger.Info().Interface("data", map[string]any{"API-Key": "opaque", "pin": "123x", "count": 7}).Msg("request")
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"API-Key":"[REDACTED]"`, `"pin":"[REDACTED]"`, `"count":7`} {
		if !bytes.Contains(out.Bytes(), []byte(want)) {
			t.Fatalf("output %s lacks %s", out.Bytes(), want)
		}
	}
}

type domainPassword string

func (domainPassword) String() string { return "domain-hidden" }

func (domainPassword) MarshalJSON() ([]byte, error) { return json.Marshal("domain-hidden") }

func TestDomainTypeAndJoinedErrors(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))
	value := domainPassword("opaque-homemade-password")
	failure := fmt.Errorf("request: %w", errors.Join(errors.New("postgres://reader:pretend-password@db.example/orders"), errors.New("token=pretend-token")))
	sink := embargozerolog.NewWriter(&out, scanner)
	logger := zerolog.New(sink)
	logger.Error().Interface("value", value).Stringer("formatted", value).Err(failure).Msg("failure")
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"opaque-homemade-password", "pretend-password", "pretend-token"} {
		if bytes.Contains(out.Bytes(), []byte(secret)) {
			t.Fatal("output leaked")
		}
	}
	if strings.Count(out.String(), "domain-hidden") < 2 {
		t.Fatal("custom methods were not honored")
	}
	if !strings.Contains(out.String(), "db.example/orders") || !strings.Contains(out.String(), "request:") {
		t.Fatal("error context was lost")
	}
}

type objectCanary struct{ value string }

func (o objectCanary) MarshalZerologObject(event *zerolog.Event) {
	event.Str("token", o.value).Str("email", "alice@example.com")
}

func TestObjectArrayAndRawJSONFields(t *testing.T) {
	t.Parallel()
	canary := "public-marshaler-canary"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail), embargo.WithDetector(literal{value: []byte(canary)}))
	r := embargotest.New(t, embargotest.WithCanary([]byte(canary)), embargotest.WithScanner(scanner))
	writer := embargozerolog.NewWriter(r.Writer("out"), scanner)
	logger := zerolog.New(writer).With().Object("pre", objectCanary{value: canary}).Logger()
	//nolint:errchkjson // Keep the explicit encoding error check required by strict errcheck.
	raw, err := json.Marshal(map[string]string{"token": canary})
	if err != nil {
		t.Fatal(err)
	}
	logger.Info().Object("object", objectCanary{value: canary}).Array("array", zerolog.Arr().Str(canary).Object(objectCanary{value: canary})).RawJSON("raw", raw).Msg("event")
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	r.ExpectJSON("out", []string{"object"}, map[string]string{"token": "[REDACTED]", "email": "[REDACTED]"}, 1)
	if !r.Check() {
		t.Fatal("custom encoded fields escaped")
	}
}

// Snapshot differences show field order and formatter changes. The semantic
// assertions run even in update mode, before accepting new output bytes.
func TestLoggerSnapshot(t *testing.T) {
	t.Parallel()
	const marker = "[REDACTED]"
	const canary = "public-fake-canary-0123456789"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN, embargo.KindCVV), embargo.WithDetector(literal{value: []byte(canary)}))
	var output bytes.Buffer
	for range 2 {
		emit(t, &output, scanner, canary)
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatal("event framing changed")
	}
	for _, line := range lines {
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		if event["pre"] != marker || event["card"] != marker || event["cvv"] != marker || event["nested"] == nil {
			t.Fatal("snapshot lost masking or structure")
		}
		nested, ok := event["nested"].(map[string]any)
		if !ok || nested["email"] != marker {
			t.Fatal("snapshot lost the nested object")
		}
		values, ok := nested["values"].([]any)
		if !ok || len(values) != 1 || values[0] != marker {
			t.Fatal("snapshot lost the nested array")
		}
		if bytes.Contains(line, []byte(canary)) || bytes.Contains(line, []byte("alice@example.com")) {
			t.Fatal("snapshot contains synthetic secret")
		}
	}
	const path = "testdata/logger.golden"
	if os.Getenv("UPDATE_SNAPSHOTS") == "1" {
		if err := os.WriteFile(path, output.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, output.Bytes()) {
		t.Fatal("logger snapshot changed; review field structure and ordering")
	}
}

type auditPanicDetector struct{}

func (auditPanicDetector) Scan([]byte) []embargo.Finding { panic("planted-panic") }
func TestWithheldRecord(t *testing.T) {
	t.Parallel()
	for _, reason := range []string{"masking error", "size limit"} {
		t.Run(reason, func(t *testing.T) {
			t.Parallel()
			scanner := embargo.NewScanner(embargo.WithKinds())
			value := "planted-value"
			if reason == "masking error" {
				scanner = embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(auditPanicDetector{}))
			} else {
				value += strings.Repeat("x", 1<<20)
			}
			var out bytes.Buffer
			sink := embargozerolog.NewWriter(&out, scanner)
			logger := zerolog.New(sink)
			logger.Warn().Time("time", time.Unix(7, 0).UTC()).Str("planted-key", value).Msg("planted-message")
			var got map[string]any
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatalf("missing fallback: %v", err)
			}
			message := got["msg"]
			if message == nil {
				message = got["message"]
			}
			if message != "embargo: record withheld ("+reason+")" || got["withheld_attributes"] != float64(1) || got["level"] != "warn" || strings.Contains(out.String(), "planted") {
				t.Fatal(out.String())
			}
			if got["ts"] != nil || got["time"] != nil || got["timestamp"] != nil {
				t.Fatal("unproven timestamp survived", got)
			}
		})
	}
}

func TestWithheldUserTimestampField(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"ts", "time", "timestamp", "custom_clock"} {
		for _, text := range []bool{false, true} {
			var out bytes.Buffer
			writer := embargozerolog.NewWriter(&out, embargo.NewScanner())
			logger := zerolog.New(writer)
			event := logger.Info()
			if text {
				event.Str(key, "2026-11-16T00:00:00.4111111111111111Z")
			} else {
				event.Int64(key, 4111111111111111)
			}
			event.Str("body", strings.Repeat("x", 1<<20)).Msg("upload")
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), "4111111111111111") || !strings.Contains(out.String(), "record withheld") {
				t.Fatalf("user timestamp survived: %s", out.String())
			}
		}
	}
}
