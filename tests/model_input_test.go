package tests

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/nao1215/embargo"
)

func TestQuintInputReplay(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("models/input.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Traces [][]struct {
			Op       string `json:"op"`
			Value    int    `json:"value"`
			Snapshot int    `json:"snapshot"`
			Failed   bool   `json:"failed"`
		} `json:"traces"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Traces) != 64 {
		t.Fatal("missing model traces")
	}
	values := []string{"", "model-alpha", "model-beta"}
	seen := map[string]bool{}
	for _, trace := range fixture.Traces {
		var input embargo.Input[[]byte]
		var snapshot embargo.Secret[[]byte]
		for _, state := range trace {
			seen[state.Op] = true
			var err error
			switch state.Op {
			case "init":
			case "scanA", "scanB":
				source := []byte(values[1])
				if state.Op == "scanB" {
					source = []byte(values[2])
				}
				err = input.Scan(source)
				source[0] = 'X'
			case "scanNil":
				err = input.Scan(nil)
			case "scanInvalid":
				err = input.Scan(42)
			case "text":
				err = input.UnmarshalText([]byte(values[1]))
			case "marker":
				err = input.UnmarshalText([]byte(referenceMarker))
			case "json":
				err = input.UnmarshalJSON([]byte(`"bW9kZWwtYWxwaGE="`))
			case "badJSON":
				err = input.UnmarshalJSON([]byte(`{"opaque-private-value":42}`))
			case "snapshot":
				snapshot = input.Secret()
			default:
				t.Fatal("unknown model operation")
			}
			if (err != nil) != state.Failed || (err != nil && err.Error() != "embargo: invalid input") {
				t.Fatalf("error contract after %s", state.Op)
			}
			if string(input.Secret().Reveal()) != values[state.Value] || string(snapshot.Reveal()) != values[state.Snapshot] {
				t.Fatalf("state mismatch after %s", state.Op)
			}
			if input.String() != referenceMarker || snapshot.String() != referenceMarker {
				t.Fatal("display revealed model state")
			}
		}
	}
	if len(seen) != 10 {
		t.Fatal("trace generation missed an Input operation")
	}
}
