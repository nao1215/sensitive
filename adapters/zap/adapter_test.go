package embargozap_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

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
