package embargozerolog_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

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
