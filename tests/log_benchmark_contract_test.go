package tests

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestBenchmarkEventsMaskTheirSensitiveValues(t *testing.T) {
	t.Parallel()
	for name, attrs := range comparisonEvents() {
		for _, mode := range []string{comparisonMasqName, comparisonEmbargoName} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				t.Parallel()
				checkBenchmarkEvent(t, name, mode, attrs)
			})
		}
	}
}

func checkBenchmarkEvent(t *testing.T, name, mode string, attrs []slog.Attr) {
	t.Helper()
	var out bytes.Buffer
	slog.New(comparisonHandler(mode, &out)).LogAttrs(t.Context(), slog.LevelInfo, "request", attrs...)
	for _, secret := range []string{comparisonEmail, comparisonPassword, comparisonRecovery, "4111111111111111"} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("benchmark configuration leaked its sensitive input")
		}
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if name == comparisonNested || name == comparisonMap {
		field := "user"
		if name == comparisonMap {
			field = "data"
		}
		if raw := record[field]; len(raw) == 0 || raw[0] != '{' {
			t.Fatal("benchmark lost its nested object")
		}
	}
}
