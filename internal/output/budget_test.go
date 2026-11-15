package output

import (
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

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

func TestScanBudgetBoundary(t *testing.T) {
	t.Parallel()
	counter := &measuredDetector{}
	scanner := &eventScanner{scanner: embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(counter)), remaining: 6}
	if got, err := scanner.maskScalar("abc", "k"); err != nil || got != "abc" {
		t.Fatal("exact budget should preserve a clean value")
	}
	for _, context := range []string{"", "key"} {
		if _, err := scanner.maskScalar("x", context); err == nil {
			t.Fatal("exhausted budget accepted another scan")
		}
	}
	if counter.bytes != 6 {
		t.Fatal("over-budget input reached the detector")
	}
}
