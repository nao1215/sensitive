package embargologrus_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"testing"

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
			if err == nil || len(data) != 0 || first.calls != want || second.calls != 0 || next.calls != want {
				t.Fatalf("err=%v bytes=%d scans=%d/%d formats=%d want=%d", err, len(data), first.calls, second.calls, next.calls, want)
			}
		})
	}
}
