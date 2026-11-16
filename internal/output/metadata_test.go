package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/saferecord"
)

func TestMetadataNeverRetainsOriginalFields(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		`{"time":"1970-01-01T00:00:07Z","level":"warn","msg":"planted-message","planted-key":{"nested":"planted-value"},"second":[1,2]}`,
		`{"ts":7,"level":"WARN","message":"planted-message","planted-key":"escaped\"planted-value","second":true}`,
		`{"timestamp":7.5,"level":"info","planted-key":null,"second":{}}`,
	} {
		for _, chunk := range []int{1, 7, len(input)} {
			var meta eventMetadata
			for data := []byte(input); len(data) > 0; {
				n := min(chunk, len(data))
				meta.feed(data[:n])
				data = data[n:]
			}
			raw := meta.fallback(saferecord.ErrSizeLimit)
			var got map[string]any
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if meta.count != 2 || bytes.Contains(raw, []byte("planted")) || got["level"] == nil {
				t.Fatalf("wrong diagnostic: %s", raw)
			}
		}
	}
}

func TestMetadataRejectsUntrustedMetadata(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		`{"time":"planted-time","level":"planted-level"}`,
		`{"time":{},"level":[]}`,
		`{"time":NaN,"level":1}`,
		`{"time":"` + strings.Repeat("x", 200) + `","level":"` + strings.Repeat("x", 200) + `"}`,
		`{"` + strings.Repeat("x", 200) + `":"planted"}`,
		`{"time":"\u0000","level":"\u0000"}`,
	} {
		var meta eventMetadata
		meta.feed([]byte(input))
		raw := meta.fallback(saferecord.ErrMasking)
		if meta.level != nil || bytes.Contains(raw, []byte("planted")) {
			t.Fatalf("unsafe metadata: %s", raw)
		}
	}
}

func TestOversizedSplitRecordRetainsOnlyDiagnosticMetadata(t *testing.T) {
	t.Parallel()
	var sink bytes.Buffer
	writer := NewWriter(&sink, embargo.NewScanner(embargo.WithKinds()))
	chunks := []string{`{"level":"error","ts":7,"planted-key":"`, strings.Repeat("x", maxEventBytes), `planted-value","late-key":3}` + "\n", `{"ok":true}` + "\n"}
	for _, chunk := range chunks {
		if _, err := writer.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
		if len(writer.pending) > maxEventBytes {
			t.Fatal("retained oversized input")
		}
	}
	if bytes.Contains(sink.Bytes(), []byte("planted")) || !strings.Contains(sink.String(), `"withheld_attributes":2`) || !strings.HasSuffix(sink.String(), "{\"ok\":true}\n") {
		t.Fatal(sink.String())
	}
}

func TestMetadataRejectsUserTimeFields(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"ts", "time", "timestamp"} {
		for _, value := range []string{`4111111111111111`, `"2026-11-16T00:00:00.4111111111111111Z"`} {
			var meta eventMetadata
			meta.feed([]byte(`{"` + key + `":7,"` + key + `":` + value + `}`))
			if got := meta.fallback(saferecord.ErrSizeLimit); bytes.Contains(got, []byte("4111111111111111")) {
				t.Fatalf("user time survived: %s", got)
			}
			var onlyUser eventMetadata
			onlyUser.feed([]byte(`{"` + key + `":` + value + `}`))
			if got := onlyUser.fallback(saferecord.ErrMasking); bytes.Contains(got, []byte("4111111111111111")) {
				t.Fatalf("unproven time survived: %s", got)
			}
		}
	}
}
