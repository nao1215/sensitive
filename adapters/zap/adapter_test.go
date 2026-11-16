package embargozap_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/nao1215/embargo"
	embargozap "github.com/nao1215/embargo/adapters/zap"
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

func emit(t *testing.T, out io.Writer, scanner *embargo.Scanner, canary string) {
	t.Helper()
	sink := embargozap.NewWriteSyncer(zapcore.AddSync(out), scanner)
	logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zapcore.EncoderConfig{MessageKey: "msg"}), sink, zap.DebugLevel))
	logger = logger.With(zap.String("pre", canary)).Named("alice@example.com")
	logger.Info(canary, zap.String(canary, "alice@example.com"), zap.Int64("card", 4111111111111111), zap.Int("cvv", 123), zap.Any("secret", embargo.NewSecret(canary)), zap.Any("nested", map[string]any{"email": "alice@example.com", "values": []string{canary}}), zap.Error(errors.New(canary)))
	if err := logger.Sync(); err != nil {
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
	sink := embargozap.NewWriteSyncer(zapcore.AddSync(r.Writer("logs")), scanner)
	logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zapcore.EncoderConfig{MessageKey: "msg"}), sink, zap.DebugLevel))
	logger.Info("encoded", zap.Binary("binary", r.Canary()))
	if err := logger.Sync(); err != nil {
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
	sink := embargozap.NewWriteSyncer(zapcore.AddSync(&out), scanner)
	logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zapcore.EncoderConfig{MessageKey: "msg"}), sink, zap.DebugLevel))
	logger.Info("request", zap.Any("data", map[string]any{"API-Key": "opaque", "pin": "123x", "count": 7}))
	if err := logger.Sync(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"API-Key":"[REDACTED]"`, `"pin":"[REDACTED]"`, `"count":7`} {
		if !bytes.Contains(out.Bytes(), []byte(want)) {
			t.Fatalf("output %s lacks %s", out.Bytes(), want)
		}
	}
}

type sharedSink struct{ calls int }

func (s *sharedSink) Write(data []byte) (int, error) { s.calls++; return len(data), nil }

func (s *sharedSink) Sync() error { s.calls++; return nil }

func TestWriteAndSyncSerializeTheSink(t *testing.T) {
	t.Parallel()
	sink := &sharedSink{}
	writer := embargozap.NewWriteSyncer(sink, embargo.NewScanner(embargo.WithKinds()))
	var group sync.WaitGroup
	for range 20 {
		group.Go(func() {
			for range 20 {
				if _, err := writer.Write([]byte("{\"event\":\"accepted\"}\n")); err != nil {
					t.Error(err)
				}
				if err := writer.Sync(); err != nil {
					t.Error(err)
				}
			}
		})
	}
	group.Wait()
	if sink.calls != 800 {
		t.Fatal("sink calls were lost")
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
	config := zap.NewProductionEncoderConfig()
	config.TimeKey = ""
	logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(config), embargozap.NewWriteSyncer(zapcore.AddSync(&out), scanner), zap.InfoLevel))
	logger.Info("failure", zap.Any("value", value), zap.Stringer("formatted", value), zap.Error(failure))
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

func (o objectCanary) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("token", o.value)
	enc.AddString("email", "alice@example.com")
	return nil
}

type arrayCanary struct{ value string }

func (a arrayCanary) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	enc.AppendString(a.value)
	return enc.AppendObject(objectCanary(a))
}

func TestObjectArrayInlineAndReflectedFields(t *testing.T) {
	t.Parallel()
	canary := "public-marshaler-canary"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail), embargo.WithDetector(literal{value: []byte(canary)}))
	r := embargotest.New(t, embargotest.WithCanary([]byte(canary)), embargotest.WithScanner(scanner))
	writer := embargozap.NewWriteSyncer(zapcore.AddSync(r.Writer("out")), scanner)
	logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zapcore.EncoderConfig{MessageKey: "msg", NameKey: "name"}), writer, zap.InfoLevel))
	logger.With(zap.Object("pre", objectCanary{value: canary})).Named(canary).Info("event", zap.Object("object", objectCanary{value: canary}), zap.Array("array", arrayCanary{value: canary}), zap.Inline(objectCanary{value: canary}), zap.Reflect("reflected", map[string]string{"token": canary}))
	if err := logger.Sync(); err != nil {
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

type syncSink struct {
	bytes.Buffer

	syncs int
}

func (s *syncSink) Sync() error { s.syncs++; return io.ErrClosedPipe }

func TestSyncFlushesIncompleteDiagnosticAndPreservesBothErrors(t *testing.T) {
	t.Parallel()
	sink := &syncSink{}
	writer := embargozap.NewWriteSyncer(sink, embargo.NewScanner())
	if err := writer.Sync(); !errors.Is(err, io.ErrClosedPipe) || sink.syncs != 1 {
		t.Fatal("sync error lost")
	}
	if _, err := writer.Write([]byte(`{"partial":`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Sync(); !errors.Is(err, io.ErrClosedPipe) || !strings.Contains(err.Error(), "invalid or unmaskable JSON log event") || sink.syncs != 2 || !strings.Contains(sink.String(), "record withheld (masking error)") || strings.Contains(sink.String(), "partial") {
		t.Fatal("incomplete record was not withheld")
	}
	var record map[string]any
	if err := json.Unmarshal(sink.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if len(record) != 2 || record["msg"] != "embargo: record withheld (masking error)" || record["withheld_attributes"] != float64(1) {
		t.Fatal("partial content reached sink")
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
			sink := embargozap.NewWriteSyncer(zapcore.AddSync(&out), scanner)
			encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
			logger := zap.New(zapcore.NewCore(encoder, sink, zap.DebugLevel))
			entry := zapcore.Entry{Time: time.Unix(7, 0).UTC(), Level: zapcore.WarnLevel, Message: "planted-message"}
			if checked := logger.Check(entry.Level, entry.Message); checked != nil {
				checked.Time = entry.Time
				checked.Write(zap.String("planted-key", value))
			}
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
			if got["ts"] != float64(7) && got["time"] != "1970-01-01T00:00:07Z" {
				t.Fatal("timestamp lost", got)
			}
		})
	}
}
