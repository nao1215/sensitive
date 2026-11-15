package tests

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/nao1215/embargo"
)

const (
	metamorphicMessageKey = "message"
	metamorphicCountKey   = "count"
	referenceIBANKind     = "iban"
	referenceMarker       = "[REDACTED]"
)

// These relations compare public results, without deriving expected detections
// from another copy of a parser. Context-sensitive formats need line boundaries.
func TestMetamorphicIndependentLines(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		lines := rapid.SliceOfN(rapid.SampledFrom([]string{
			"hello", "email=alice@example.com", "pan=4111111111111111", "password=synthetic-value",
			"endpoint=192.0.2.1", "IBAN GB82 WEST 1234 5698 7654 32", "SWIFT: DEUTDEFF", referenceMarker,
		}), 1, 12).Draw(t, "independent lines")
		scanner := embargo.NewScanner(embargo.WithAll())
		for _, line := range lines {
			checkLineRelations(t, scanner, line)
		}
		joined := strings.Join(lines, "\n")
		want := findingsByLine(scanner, lines)
		if got := scanner.ScanString(joined); !slices.Equal(got, want) {
			t.Fatalf("line composition: %q: %v != %v", joined, got, want)
		}
		slices.Reverse(lines)
		if got := scanner.ScanString(strings.Join(lines, "\n")); !slices.Equal(got, findingsByLine(scanner, lines)) {
			t.Fatal("reordering independent lines changed a finding")
		}
	})
}

type relationTB interface {
	Helper()
	Fatal(...any)
	Fatalf(string, ...any)
}

func findingsByLine(scanner *embargo.Scanner, lines []string) []embargo.Finding {
	var result []embargo.Finding
	offset := 0
	for _, line := range lines {
		for _, finding := range scanner.ScanString(line) {
			finding.Start += offset
			finding.End += offset
			result = append(result, finding)
		}
		offset += len(line) + 1
	}
	return result
}

func checkLineRelations(t relationTB, scanner *embargo.Scanner, line string) {
	t.Helper()
	original := scanner.ScanString(line)
	const prefix = "public prelude\n"
	shifted := scanner.ScanString(prefix + line + "\npublic epilogue")
	for i := range shifted {
		shifted[i].Start -= len(prefix)
		shifted[i].End -= len(prefix)
	}
	if !slices.Equal(original, shifted) {
		t.Fatal("unrelated lines changed a finding")
	}
	masked := embargo.Mask(line, original)
	if again := scanner.ScanString(masked); len(again) != 0 {
		t.Fatalf("mask exposes another finding: kinds=%v", again)
	}
	if embargo.Mask(masked, scanner.ScanString(masked)) != masked {
		t.Fatal("mask is not idempotent")
	}
}

func TestMetamorphicKindsAndPercent(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		kind := rapid.SampledFrom([]embargo.Kind{embargo.KindEmail, embargo.KindPAN, embargo.KindIPAddr}).Draw(t, "kind")
		other := rapid.SampledFrom([]embargo.Kind{embargo.KindCredential, embargo.KindMyNumber, embargo.KindIBAN}).Draw(t, "other")
		value := chars(t, "abcdefghijklmnopqrstuvwxyz", rapid.IntRange(1, 20).Draw(t, "length")) + "@example.com"
		raw := "value=(" + value + ") pan=4111111111111111 password=fake-value"
		a := embargo.NewScanner(embargo.WithKinds(kind)).ScanString(raw)
		b := embargo.NewScanner(embargo.WithKinds(other)).ScanString(raw)
		union := embargo.NewScanner(embargo.WithKinds(kind, other)).ScanString(raw)
		want := make(map[embargo.Finding]bool)
		for _, finding := range append(a, b...) {
			want[finding] = true
		}
		if len(union) != len(want) {
			t.Fatal("kind union count")
		}
		for _, finding := range union {
			if !want[finding] {
				t.Fatal("kind selection changes finding")
			}
		}
		// Credential grammar intentionally sees original URL delimiters; arbitrary
		// percent encoding is only an invariant for built-ins that decode one layer.
		scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
		encoded := make([]byte, 0, len(value)*3)
		for _, c := range []byte(value) {
			encoded = append(encoded, '%', "0123456789ABCDEF"[c>>4], "0123456789ABCDEF"[c&15])
		}
		got := scanner.ScanString("(" + string(encoded) + ")")
		if len(got) != 1 || got[0].Start != 1 || got[0].End != 1+len(encoded) || got[0].Kind != embargo.KindEmail {
			t.Fatal("encoded finding does not cover original bytes")
		}
	})
}

func TestMetamorphicJSONAndSlog(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// #nosec G101 -- Deliberately fake credentials exercise masking.
		value := map[string]any{"email": chars(t, "abcxyz", rapid.IntRange(1, 20).Draw(t, "name")) + "@example.com", "password": "opaque-fake-value", metamorphicCountKey: rapid.IntRange(0, 99).Draw(t, metamorphicCountKey), "nested": []any{"public", true, nil}}
		checkJSONPaths(t, value)
	})
}

func checkJSONPaths(t relationTB, value map[string]any) {
	t.Helper()
	scanner := embargo.NewScanner(embargo.WithAll())
	compact, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	pretty, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	masked, err := scanner.MaskJSON(compact)
	if err != nil {
		t.Fatal(err)
	}
	other, err := scanner.MaskJSON(pretty)
	if err != nil || !bytes.Equal(masked, other) {
		t.Fatal("JSON whitespace changes masked document")
	}
	var buffer bytes.Buffer
	handler := embargo.NewSlogHandler(slog.NewJSONHandler(&buffer, nil), scanner)
	record := slog.NewRecord(time.Time{}, slog.LevelInfo, "public event", 0)
	record.AddAttrs(slog.Any("value", value))
	if err := handler.Handle(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	var event map[string]json.RawMessage
	if err := json.Unmarshal(buffer.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	var a, b any
	if err := json.Unmarshal(masked, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(event["value"], &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("slog and MaskJSON disagree")
	}
}

// Licensed data stays in the owner's cache. CI runs the synthetic generators;
// the round evidence records a full replay and never commits raw public logs.
//
//nolint:paralleltest // This opt-in measurement reads the full corpus serially.
func TestMetamorphicRealLogs(t *testing.T) {
	cache := os.Getenv("EMBARGO_LOG_CACHE")
	if cache == "" {
		t.Skip("set EMBARGO_LOG_CACHE to the verified round-13 cache")
	}
	scanner := embargo.NewScanner(embargo.WithAll())
	for _, name := range []string{"Apache/Apache.log", "Linux/Linux.log", "Android/Android_2k.log", "HDFS/HDFS_2k.log", "OpenSSH/OpenSSH.log", "Zookeeper/Zookeeper.log", "BGL/BGL_2k.log", "Spark/Spark_2k.log"} {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(filepath.Join(cache, name)) // #nosec G304 G703 -- Fixed corpus paths under the operator-selected cache.
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if closeErr := f.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
			}()
			reader := bufio.NewScanner(f)
			reader.Buffer(make([]byte, 4096), 16<<20)
			count := 0
			for reader.Scan() {
				line := reader.Text()
				checkLineRelations(t, scanner, line)
				checkJSONPaths(t, map[string]any{metamorphicMessageKey: line})
				count++
			}
			if err := reader.Err(); err != nil {
				t.Fatal(err)
			}
			t.Logf("checked %d lines", count)
		})
	}
}
