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
