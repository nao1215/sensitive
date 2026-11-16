package output

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

func TestJSONMasksDecodedKeysValuesAndNumbers(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN))
	got, err := JSON([]byte(`{"alice\u0040example.com":["alice\u0040example.com",4111111111111111,{"ok":true}],"x":null,"x":"clean"}`), scanner)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"[REDACTED]\":[\"[REDACTED]\",\"[REDACTED]\",{\"ok\":true}],\"x\":null,\"x\":\"clean\"}\n"
	if string(got) != want {
		t.Fatalf("unexpected sanitized structure: %s", got)
	}
}

func TestJSONRejectsMalformedOversizedAndDeepInput(t *testing.T) {
	t.Parallel()
	for _, input := range []string{`{"x":`, `[]`, strings.Repeat(" ", 1<<20) + "{}", `{"x":1} {"y":2}`, "{\"x\":\"" + strings.Repeat("a", 1<<20) + "\"}", `{"x":` + strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65) + "}"} {
		if got, err := JSON([]byte(input), embargo.NewScanner()); err == nil || got != nil {
			t.Fatal("invalid event escaped")
		}
	}
}

func TestJSONUsesFieldNamesForContextDetectors(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCVV, embargo.KindCardExpiry, embargo.KindBankAccount))
	got, err := JSON([]byte(`{"cvv":123,"expiry":"12/28","bank account":"12345678","nested":{"cvv":["456",789]}}`), scanner)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{\"cvv\":\"[REDACTED]\",\"expiry\":\"[REDACTED]\",\"bank account\":\"[REDACTED]\",\"nested\":{\"cvv\":[\"[REDACTED]\",\"[REDACTED]\"]}}\n" {
		t.Fatal("field context was lost")
	}
}

func TestJSONOutputLimitIncludesTerminatingNewline(t *testing.T) {
	t.Parallel()
	// A custom formatter need not terminate its object; JSON adds that byte.
	input := []byte(`{"x":"` + strings.Repeat("a", maxEventBytes-len(`{"x":""}`)) + `"}`)
	if data, err := JSON(input, embargo.NewScanner(embargo.WithKinds())); err == nil || data != nil {
		t.Fatal("output exceeded the complete event byte limit")
	}
}

type cancelScan struct {
	cancel context.CancelFunc
	calls  int
}

func (d *cancelScan) Scan([]byte) []embargo.Finding { d.calls++; d.cancel(); return nil }

func TestJSONContextCancellation(t *testing.T) {
	t.Parallel()
	for _, before := range []bool{false, true} {
		t.Run(strconv.FormatBool(before), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if before {
				cancel()
			}
			detector := &cancelScan{cancel: cancel}
			scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(detector))
			data, err := JSONContext(ctx, []byte(`{"first":"public","second":"retained"}`), scanner)
			want := 1
			if before {
				want = 0
			}
			if err == nil || len(data) != 0 || detector.calls != want {
				t.Fatalf("err=%v bytes=%d scans=%d want=%d", err, len(data), detector.calls, want)
			}
		})
	}
	var missing context.Context
	if data, err := JSONContext(missing, []byte(`{}`), embargo.NewScanner()); err == nil || len(data) != 0 {
		t.Fatal("nil context accepted")
	}
}

type measuredDetector struct{ bytes int }

func (d *measuredDetector) Scan(data []byte) []embargo.Finding {
	d.bytes += len(data)
	return nil
}

func TestJSONBoundsRepeatedFieldContext(t *testing.T) {
	t.Parallel()
	counter := &measuredDetector{}
	scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(counter))
	input := `{"` + strings.Repeat("k", 1<<14) + `":[` + strings.Repeat("0,", 511) + "0]}"
	data, err := JSON([]byte(input), scanner)
	if err == nil || data != nil {
		t.Fatal("event exceeded the cumulative scan budget")
	}
	if counter.bytes > 4<<20 {
		t.Fatalf("scanned %d bytes for one small event", counter.bytes)
	}
}
