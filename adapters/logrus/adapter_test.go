package embargologrus_test

import (
	"bytes"
	"errors"
	"io"
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
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN), embargo.WithDetector(literal{value: []byte(canary)}))
	r := embargotest.New(t, embargotest.WithCanary([]byte(canary)), embargotest.WithScanner(scanner))
	emit(t, r.Writer("logs"), scanner, canary)
	//nolint:goconst // Spell out each field expectation as an independent output contract.
	r.ExpectJSON("logs", nil, map[string]string{"msg": "[REDACTED]", "pre": "[REDACTED]", "card": "[REDACTED]", "secret": "[REDACTED]"}, 1)
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
	logger.WithField("pre", canary).WithFields(logrus.Fields{canary: "alice@example.com", "card": int64(4111111111111111), "secret": embargo.NewSecret(canary), "nested": map[string]any{"email": "alice@example.com", "values": []string{canary}}, "error": errors.New(canary)}).Info(canary)
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
