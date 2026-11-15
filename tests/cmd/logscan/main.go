// Command logscan measures cached public logs without copying them into the repository.
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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nao1215/embargo"
)

type dataset struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Split  string `json:"split"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Lines  int    `json:"lines"`
}
type manifest struct {
	Kinds          []embargo.Kind            `json:"kinds"`
	Configurations map[string][]embargo.Kind `json:"configurations"`
	Datasets       []dataset                 `json:"datasets"`
}
type sample struct {
	Value   string          `json:"value"`
	ID      string          `json:"id"`
	Text    string          `json:"text"`
	Finding embargo.Finding `json:"finding"`
	Line    int             `json:"line"`
}
type result struct {
	Counts         map[string]map[embargo.Kind]int `json:"counts"`
	Samples        map[embargo.Kind][]sample       `json:"samples"`
	Dataset        string                          `json:"dataset"`
	FindingsSHA256 string                          `json:"findings_sha256"`
	Bytes          int64                           `json:"bytes"`
	Lines          int                             `json:"lines"`
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
	manifestPath := flag.String("manifest", "../doc/real-logs-manifest.json", "pinned dataset manifest")
	cache := flag.String("cache", "", "external cache directory")
	split := flag.String("split", "development", "development or held")
	output := flag.String("output", "", "external result file (includes sampled public logs)")
	flag.Parse()
	if *cache == "" || *output == "" || (*split != "development" && *split != "held") {
		return errors.New("cache, output and a valid split are required")
	}
	data, err := os.ReadFile(*manifestPath)
	if err != nil {
		return err
	}
	var m manifest
	if decodeErr := json.Unmarshal(data, &m); decodeErr != nil {
		return decodeErr
	}
	scanners := map[string]*embargo.Scanner{"all": embargo.NewScanner(embargo.WithAll()), "default": embargo.NewScanner()}
	for name, kinds := range m.Configurations {
		scanners[name] = embargo.NewScanner(embargo.WithKinds(kinds...))
	}
	singles := map[embargo.Kind]*embargo.Scanner{}
	for _, kind := range m.Kinds {
		singles[kind] = embargo.NewScanner(embargo.WithKinds(kind))
	}
	var results []result
	for _, d := range m.Datasets {
		if d.Split != *split {
			continue
		}
		r, measureErr := measure(&d, *cache, scanners, singles)
		if measureErr != nil {
			return measureErr
		}
		results = append(results, r)
	}
	out, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	const privateMode = 0o600
	return os.WriteFile(*output, append(out, '\n'), privateMode)
}

//nolint:gocognit // Keep the independent scanner and actual handler checks next to the measured line.
func measure(d *dataset, cache string, scanners map[string]*embargo.Scanner, singles map[embargo.Kind]*embargo.Scanner) (r result, err error) {
	r = result{Dataset: d.Name, Counts: map[string]map[embargo.Kind]int{}, Samples: map[embargo.Kind][]sample{}}
	path, err := filepath.Localize(d.Path)
	if err != nil {
		return r, err
	}
	// #nosec G304 -- Localized relative path from the committed checksum manifest, rooted in the explicit cache.
	file, err := os.Open(filepath.Join(cache, path))
	if err != nil {
		return r, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	digest := sha256.New()
	hashed := io.TeeReader(file, digest)
	lines := bufio.NewScanner(hashed)
	const maxLogLine = 4 << 20
	lines.Buffer(make([]byte, bufio.MaxScanTokenSize), maxLogLine)
	findingsDigest := sha256.New()
	encoder := json.NewEncoder(findingsDigest)
	var output bytes.Buffer
	handler := embargo.NewSlogHandler(slog.NewJSONHandler(&output, nil), scanners["default"])
	for name := range scanners {
		r.Counts[name] = map[embargo.Kind]int{}
	}
	for lines.Scan() {
		r.Lines++
		text := lines.Text()
		all := scanners["all"].ScanString(text)
		if encodeErr := encoder.Encode(all); encodeErr != nil {
			return r, encodeErr
		}
		for kind, scanner := range singles {
			individual := scanner.ScanString(text)
			selected := slices.DeleteFunc(slices.Clone(all), func(f embargo.Finding) bool { return f.Kind != kind })
			if !slices.Equal(individual, selected) {
				return r, fmt.Errorf("single/all mismatch: %s line %d kind %s", d.Name, r.Lines, kind)
			}
		}
		for name, scanner := range scanners {
			findings := all
			if name != "all" {
				findings = scanner.ScanString(text)
			}
			for _, f := range findings {
				r.Counts[name][f.Kind]++
			}
			if name == "default" {
				output.Reset()
				record := slog.NewRecord(time.Time{}, slog.LevelInfo, text, 0)
				if handleErr := handler.Handle(context.Background(), record); handleErr != nil {
					return r, handleErr
				}
				var decoded struct {
					Msg string `json:"msg"`
				}
				if decodeErr := json.Unmarshal(output.Bytes(), &decoded); decodeErr != nil {
					return r, decodeErr
				}
				if decoded.Msg != string([]rune(embargo.Mask(text, findings))) {
					return r, fmt.Errorf("handler mismatch: %s line %d", d.Name, r.Lines)
				}
			}
		}
		for _, f := range all {
			id := fmt.Sprintf("%s:%d:%s:%d:%d", d.Name, r.Lines, f.Kind, f.Start, f.End)
			sum := sha256.Sum256([]byte(id))
			pick := sample{ID: hex.EncodeToString(sum[:]), Line: r.Lines, Finding: f, Text: text, Value: text[f.Start:f.End]}
			values := r.Samples[f.Kind]
			const sampleSize = 40
			if len(values) == sampleSize && pick.ID >= values[len(values)-1].ID {
				continue
			}
			values = append(values, pick)
			slices.SortFunc(values, func(a, b sample) int { return strings.Compare(a.ID, b.ID) })
			if len(values) > sampleSize {
				values = values[:sampleSize]
			}
			r.Samples[f.Kind] = values
		}
	}
	if scanErr := lines.Err(); scanErr != nil {
		return r, scanErr
	}
	stat, err := file.Stat()
	if err != nil {
		return r, err
	}
	r.Bytes = stat.Size()
	if r.Bytes != d.Bytes || r.Lines != d.Lines || hex.EncodeToString(digest.Sum(nil)) != d.SHA256 {
		return r, fmt.Errorf("cached dataset differs from manifest: %s", d.Name)
	}
	r.FindingsSHA256 = hex.EncodeToString(findingsDigest.Sum(nil))
	return r, nil
}
