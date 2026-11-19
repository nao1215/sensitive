package embargologrus_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nao1215/embargo"
	embargologrus "github.com/nao1215/embargo/adapters/logrus"
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
	r.ExpectJSON("logs", nil, map[string]string{"msg": "[REDACTED]", "pre": "[REDACTED]", "card": "[REDACTED]", "cvv": "[REDACTED]", "secret": "[REDACTED]"}, 1)
	if !r.Check() {
		t.Fatal("real logger output failed inspection")
	}
}

//nolint:goconst // Keep the raw values visible in this real logger acceptance path.
func emit(t *testing.T, out io.Writer, scanner *embargo.Scanner, canary string) {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(out)
	logger.SetFormatter(embargologrus.NewFormatter(&logrus.JSONFormatter{DisableTimestamp: true}, scanner))
	logger.WithField("pre", canary).WithFields(logrus.Fields{canary: "alice@example.com", "card": int64(4111111111111111), "cvv": 123, "secret": embargo.NewSecret(canary), "nested": map[string]any{"email": "alice@example.com", "values": []string{canary}}, "error": errors.New(canary)}).Info(canary)
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
	logger := logrus.New()
	logger.SetOutput(r.Writer("logs"))
	logger.SetFormatter(embargologrus.NewFormatter(&logrus.JSONFormatter{DisableTimestamp: true}, scanner))
	logger.WithField("binary", r.Canary()).Info("encoded")
	r.Expect("logs", func(data []byte) bool { return bytes.Contains(data, []byte("encoded")) })
	if r.Check() || !observation.failed {
		t.Fatal("encoded canary must expose the documented runtime detection limit")
	}
}

func TestSensitiveKeyPolicy(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithSensitiveKeys("api_key", "pin"))
	var out bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&out)
	logger.SetFormatter(embargologrus.NewFormatter(&logrus.JSONFormatter{DisableTimestamp: true}, scanner))
	logger.WithField("data", map[string]any{"API-Key": "opaque", "pin": "123x", "count": 7}).Info("request")
	for _, want := range []string{`"API-Key":"[REDACTED]"`, `"pin":"[REDACTED]"`, `"count":7`} {
		if !bytes.Contains(out.Bytes(), []byte(want)) {
			t.Fatalf("output %s lacks %s", out.Bytes(), want)
		}
	}
}

type cancelingDetector struct {
	cancel context.CancelFunc
	calls  int
}

func (d *cancelingDetector) Scan([]byte) []embargo.Finding { d.calls++; d.cancel(); return nil }

type countingFormatter struct{ calls int }

func (f *countingFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	f.calls++
	return (&logrus.JSONFormatter{DisableTimestamp: true}).Format(entry)
}

func TestEntryContextCancellation(t *testing.T) {
	t.Parallel()
	for _, before := range []bool{false, true} {
		t.Run(strconv.FormatBool(before), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if before {
				cancel()
			}
			first := &cancelingDetector{cancel: cancel}
			second := &cancelingDetector{cancel: cancel}
			scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(first), embargo.WithDetector(second))
			next := &countingFormatter{}
			entry := logrus.NewEntry(logrus.New()).WithContext(ctx).WithField("field", "public")
			data, err := embargologrus.NewFormatter(next, scanner).Format(entry)
			want := 1
			if before {
				want = 0
			}
			if err != nil || !bytes.Contains(data, []byte("record withheld (canceled)")) || first.calls != want || second.calls != 0 || next.calls != want {
				t.Fatalf("err=%v bytes=%d scans=%d/%d formats=%d want=%d", err, len(data), first.calls, second.calls, next.calls, want)
			}
		})
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
	logger := logrus.New()
	logger.SetOutput(&out)
	logger.SetFormatter(embargologrus.NewFormatter(&logrus.JSONFormatter{DisableTimestamp: true}, scanner))
	logger.WithFields(logrus.Fields{"value": value, "formatted": value.String(), "error": failure}).Error("failure")
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

type brokenFormatter struct{ panicValue bool }

func (f brokenFormatter) Format(*logrus.Entry) ([]byte, error) {
	if f.panicValue {
		panic("public-fake-canary")
	}
	return []byte("public-fake-canary"), errors.New("public-fake-canary")
}

func TestFormatterErrorsAndUnsupportedTextFailClosed(t *testing.T) {
	t.Parallel()
	for _, next := range []logrus.Formatter{brokenFormatter{}, brokenFormatter{panicValue: true}, &logrus.TextFormatter{DisableTimestamp: true}} {
		formatter := embargologrus.NewFormatter(next, embargo.NewScanner())
		entry := &logrus.Entry{Message: "public-fake-canary", Level: logrus.InfoLevel}
		data, err := formatter.Format(entry)
		if err != nil || !bytes.Contains(data, []byte("record withheld (masking error)")) || bytes.Contains(data, []byte("canary")) {
			t.Fatal("unsafe formatting failure")
		}
		if entry.Message != "public-fake-canary" {
			t.Fatal("entry mutated")
		}
	}
}

type objectCanary struct{ value string }

func (o objectCanary) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"token": o.value, "email": "alice@example.com"})
}

func TestCustomJSONFields(t *testing.T) {
	t.Parallel()
	canary := "public-marshaler-canary"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail), embargo.WithDetector(literal{value: []byte(canary)}))
	r := embargotest.New(t, embargotest.WithCanary([]byte(canary)), embargotest.WithScanner(scanner))
	logger := logrus.New()
	logger.SetOutput(r.Writer("out"))
	logger.SetFormatter(embargologrus.NewFormatter(&logrus.JSONFormatter{DisableTimestamp: true}, scanner))
	logger.WithField("pre", objectCanary{value: canary}).WithField("object", objectCanary{value: canary}).Info("event")
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
	for _, reason := range []string{"masking error", "size limit", "canceled"} {
		t.Run(reason, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			scanner := embargo.NewScanner(embargo.WithKinds())
			value := "planted-value"
			if reason == "masking error" {
				scanner = embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(auditPanicDetector{}))
			}
			if reason == "size limit" {
				value += strings.Repeat("x", 1<<20)
			}
			if reason == "canceled" {
				cancel()
			}
			var out bytes.Buffer
			logger := logrus.New()
			logger.SetOutput(&out)
			logger.SetFormatter(embargologrus.NewFormatter(&logrus.JSONFormatter{}, scanner))
			logger.WithContext(ctx).WithTime(time.Unix(7, 0).UTC()).WithField("planted-key", value).Warn("planted-message")
			var got map[string]any
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatalf("missing fallback: %v", err)
			}
			if len(got) != 4 || got["msg"] != "embargo: record withheld ("+reason+")" || got["withheld_attributes"] != float64(1) || got["time"] != "1970-01-01T00:00:07Z" || got["level"] != "warning" || strings.Contains(out.String(), "planted") {
				t.Fatal(out.String())
			}
		})
	}
}

func TestWithheldSchemaProperty(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	formatter := embargologrus.NewFormatter(&logrus.JSONFormatter{}, embargo.NewScanner())
	for _, level := range logrus.AllLevels {
		for count := range 9 {
			data := make(logrus.Fields)
			for index := range count {
				data[fmt.Sprintf("planted-%d", index)] = map[string]any{"nested": "private@example.com"}
			}
			encoded, err := formatter.Format(&logrus.Entry{Logger: logrus.New(), Context: ctx, Time: time.Unix(7, 0).UTC(), Level: level, Message: "planted-message", Data: data})
			if err != nil {
				t.Fatal(err)
			}
			var record map[string]any
			if err := json.Unmarshal(encoded, &record); err != nil {
				t.Fatal(err)
			}
			if len(record) != 4 || record["level"] != level.String() || record["time"] != "1970-01-01T00:00:07Z" || record["msg"] != "embargo: record withheld (canceled)" || record["withheld_attributes"] != float64(count) {
				t.Fatalf("level=%s count=%d: %s", level, count, encoded)
			}
		}
	}
}

func TestNilEntryReturnsFixedError(t *testing.T) {
	t.Parallel()
	data, err := embargologrus.NewFormatter(&logrus.JSONFormatter{}, embargo.NewScanner()).Format(nil)
	if data != nil || err == nil || err.Error() != "embargo: logrus formatting failed" {
		t.Fatalf("nil entry = %q, %v", data, err)
	}
}
