package embargo

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"runtime"
	"strings"
	"testing"
	"time"
)

//nolint:gocognit // One generated tree is checked through construction, masking and descent.
func FuzzJSONPaths(f *testing.F) {
	for _, seed := range []string{"ordinary", `quote" slash\`, "listener 0.0.0.0", "token=Class@deadbeef", "123456789012.example.invalid"} {
		f.Add(seed, uint8(3), true)
	}
	f.Fuzz(func(t *testing.T, value string, depth uint8, object bool) {
		if len(value) > 4096 {
			t.Skip()
		}
		var tree any = map[string]any{"password": value, "public": true}
		for range int(depth) % 70 {
			if object {
				tree = map[string]any{"child": tree}
			} else {
				tree = []any{tree}
			}
		}
		input, err := json.Marshal(tree)
		if err != nil {
			t.Fatal(err)
		}
		output, err := NewScanner(WithKinds()).MaskJSON(input)
		if int(depth)%70 >= 64 {
			if err == nil || output != nil {
				t.Fatal("depth limit bypass")
			}
			return
		}
		if err != nil || !json.Valid(output) {
			t.Fatal("structured path broke JSON")
		}
		var got any
		if err := json.Unmarshal(output, &got); err != nil {
			t.Fatal(err)
		}
		for range int(depth) % 70 {
			if object {
				node, ok := got.(map[string]any)
				if !ok {
					t.Fatal("object shape changed")
				}
				got = node["child"]
			} else {
				node, ok := got.([]any)
				if !ok || len(node) != 1 {
					t.Fatal("array shape changed")
				}
				got = node[0]
			}
		}
		leaf, ok := got.(map[string]any)
		if !ok {
			t.Fatal("leaf shape changed")
		}
		if leaf["password"] != redactionMarker || leaf["public"] != true {
			t.Fatal("nested sensitive path lost or clean field changed")
		}
	})
}

// Budget checks run in the fuzz worker, where inputs are evaluated serially.
// The seed path also runs without t.Parallel so allocation counters are isolated.
func FuzzAdversarialBudgets(f *testing.F) {
	for _, seed := range []string{digitSeparatorRun, credentialPrefixRun, nestedPercentPrefix, ibanPrefixRun, "listener 0.0.0.0", "\"\\\n"} {
		f.Add(seed, uint8(8))
	}
	f.Fuzz(func(t *testing.T, pattern string, repeat uint8) {
		if len(pattern) > 256 {
			t.Skip()
		}
		text := strings.Repeat(pattern, int(repeat)+1)
		document, err := json.Marshal(map[string]string{"public": text})
		if err != nil {
			t.Fatal(err)
		}
		scanner := NewScanner(WithAll())
		var buffer bytes.Buffer
		handler := NewSlogHandler(slog.NewJSONHandler(&buffer, nil), scanner)
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		started := time.Now()
		Mask(text, scanner.ScanString(text))
		output, err := scanner.MaskJSON(document)
		if err != nil || !json.Valid(output) {
			t.Fatal("bounded JSON input failed")
		}
		if err := handler.Handle(context.Background(), slog.Record{Message: text}); err != nil {
			t.Fatal("bounded log event failed")
		}
		runtime.ReadMemStats(&after)
		if elapsed := time.Since(started); elapsed > 5*time.Second {
			t.Fatal("bounded input exceeded five-second processing budget")
		}
		if after.TotalAlloc-before.TotalAlloc > uint64(len(document))*512+8<<20 {
			t.Fatal("bounded input exceeded allocation amplification budget")
		}
		if bytes.Count(buffer.Bytes(), []byte{'\n'}) != 1 || !json.Valid(buffer.Bytes()) {
			t.Fatal("hostile message broke log framing")
		}
	})
}

func FuzzCredentialGrammar(f *testing.F) {
	for _, value := range []string{"synthetic", `quote" slash\`, "Class@deadbeef", "long-path/component", redactionMarker} {
		f.Add(value, uint8(0))
	}
	f.Fuzz(func(t *testing.T, value string, form uint8) {
		if len(value) > 4096 {
			t.Skip()
		}
		// JSON quoting preserves a valid assignment while fuzz changes its payload.
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		key := []string{"password", "secret", "api_key"}[int(form)%3]
		document := []byte(`{"` + key + `":` + string(raw) + `,"ok":true}`)
		scanner := NewScanner(WithKinds(KindCredential))
		output, err := scanner.MaskJSON(document)
		if err != nil || !json.Valid(output) || !bytes.Contains(output, []byte(`"ok":true`)) {
			t.Fatal("credential grammar broke JSON")
		}
		text := key + "=" + string(raw)
		masked := Mask(text, scanner.ScanString(text))
		if value != "" && value != redactionMarker && !strings.Contains(masked, redactionMarker) {
			t.Fatal("quoted credential escaped masking")
		}
	})
}
