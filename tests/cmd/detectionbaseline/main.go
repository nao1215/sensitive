// Command detectionbaseline records findings and output digests for a frozen corpus.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"unicode"

	"github.com/nao1215/embargo"
)

type entry struct {
	Source           string            `json:"source"`
	InputSHA256      string            `json:"input_sha256"`
	StructuredSHA256 string            `json:"structured_sha256,omitempty"`
	MaskedSHA256     string            `json:"masked_sha256"`
	Findings         []embargo.Finding `json:"findings"`
}

type fixture struct {
	Text string `json:"text"`
}

type dataset struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type corpusManifest struct {
	Datasets []dataset `json:"datasets"`
}

type snapshot struct {
	WithheldSHA256 string  `json:"withheld_sha256"`
	Unicode        string  `json:"unicode"`
	Entries        []entry `json:"entries"`
}

func main() {
	if err := run(); err != nil {
		if _, writeErr := fmt.Fprintln(os.Stderr, err); writeErr != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
}

func run() error {
	cache := flag.String("cache", "", "checksum-verified public log cache outside the repository")
	flag.Parse()
	if *cache == "" {
		return errors.New("public log cache required")
	}
	scanner := embargo.NewScanner()
	result := snapshot{Unicode: unicode.Version, Entries: []entry{}, WithheldSHA256: withheldDigest(scanner)}
	for _, name := range []string{"accuracy.json", "accuracy_controls.json", "detection-compatibility.json"} {
		// #nosec G304 -- Names are a fixed literal list, never caller input.
		raw, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			return err
		}
		var fixtures []fixture
		if err := json.Unmarshal(raw, &fixtures); err != nil {
			return err
		}
		for i, item := range fixtures {
			result.Entries = append(result.Entries, measure(scanner, "synthetic/"+name+"/"+strconv.Itoa(i), []byte(item.Text)))
		}
	}
	raw, err := os.ReadFile("../doc/real-logs-manifest.json")
	if err != nil {
		return err
	}
	var manifest corpusManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	for _, item := range manifest.Datasets {
		raw, err := os.ReadFile(filepath.Join(*cache, item.Path))
		if err != nil {
			return err
		}
		if digest(raw) != item.SHA256 {
			return errors.New("public log checksum mismatch")
		}
		lines := bufio.NewScanner(bytes.NewReader(raw))
		const sampleLines = 128
		for line := 1; line <= sampleLines && lines.Scan(); line++ {
			result.Entries = append(result.Entries, measure(scanner, "public/"+item.Name+"/"+strconv.Itoa(line), lines.Bytes()))
		}
		if err := lines.Err(); err != nil {
			return err
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func measure(scanner *embargo.Scanner, source string, input []byte) entry {
	findings := scanner.Scan(input)
	if findings == nil {
		findings = []embargo.Finding{}
	}
	jsonDigest := ""
	if json.Valid(input) {
		masked, err := scanner.MaskJSON(input)
		if err != nil {
			jsonDigest = digest([]byte("withheld"))
		} else {
			jsonDigest = digest(masked)
		}
	}
	return entry{StructuredSHA256: jsonDigest, Source: source, InputSHA256: digest(input), MaskedSHA256: digest([]byte(embargo.Mask(string(input), findings))), Findings: findings}
}

func withheldDigest(scanner *embargo.Scanner) string {
	var out bytes.Buffer
	handler := embargo.NewSlogHandler(slog.NewJSONHandler(&out, nil), scanner)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := handler.Handle(ctx, slog.NewRecord(time.Time{}, slog.LevelWarn, "private message", 0)); err == nil {
		panic("canceled record not withheld")
	}
	return digest(out.Bytes())
}
