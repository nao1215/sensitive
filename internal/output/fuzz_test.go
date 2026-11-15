package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

func FuzzOutputJSON(f *testing.F) {
	for _, seed := range []string{`{"email":"alice@example.com"}`, `{"card":4111111111111111}`, `{"x":null,"x":true}`, `[]`, `{"x":"\u0040"}`} {
		f.Add(seed)
	}
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN))
	f.Fuzz(func(t *testing.T, input string) {
		data, err := JSON([]byte(input), scanner)
		if err != nil {
			if data != nil {
				t.Fatal("failed event returned bytes")
			}
			return
		}
		if !json.Valid(data) || len(data) > maxEventBytes || !strings.HasSuffix(string(data), "\n") {
			t.Fatal("successful event violated output framing")
		}
		var value map[string]any
		if err := json.Unmarshal(data, &value); err != nil {
			t.Fatal(err)
		}
	})
}
