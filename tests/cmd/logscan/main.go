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
	ThresholdSamples map[string]map[embargo.Kind][]sample `json:"threshold_samples"`
	Counts           map[string]map[embargo.Kind]int      `json:"counts"`
	Samples          map[embargo.Kind][]sample            `json:"samples"`
	Dataset          string                               `json:"dataset"`
	FindingsSHA256   string                               `json:"findings_sha256"`
	Bytes            int64                                `json:"bytes"`
	Lines            int                                  `json:"lines"`
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
	const mediumThreshold, strictThreshold = .5, .7
	scanners := map[string]*embargo.Scanner{"all": embargo.NewScanner(embargo.WithAll()), "default": embargo.NewScanner(), "default50": embargo.NewScanner(embargo.WithMinConfidence(mediumThreshold)), "default70": embargo.NewScanner(embargo.WithMinConfidence(strictThreshold))}
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

// measure checks every line of one cached dataset and verifies its size, line
// count and checksum against the manifest after reading it.
func measure(d *dataset, cache string, scanners map[string]*embargo.Scanner, singles map[embargo.Kind]*embargo.Scanner) (r result, err error) {
	r = result{Dataset: d.Name, Counts: map[string]map[embargo.Kind]int{}, Samples: map[embargo.Kind][]sample{}, ThresholdSamples: map[string]map[embargo.Kind][]sample{"default50": {}, "default70": {}}}
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
	check := &lineCheck{dataset: d.Name, encoder: json.NewEncoder(findingsDigest), scanners: scanners, singles: singles, handler: nil, output: bytes.Buffer{}}
	check.handler = embargo.NewSlogHandler(slog.NewJSONHandler(&check.output, nil), scanners["default"])
	for name := range scanners {
		r.Counts[name] = map[embargo.Kind]int{}
	}
	for lines.Scan() {
		r.Lines++
		if lineErr := check.line(&r, lines.Text()); lineErr != nil {
			return r, lineErr
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

// lineCheck holds the scanners and the actual slog handler that every line of
// one dataset is measured against.
type lineCheck struct {
	encoder  *json.Encoder
	scanners map[string]*embargo.Scanner
	singles  map[embargo.Kind]*embargo.Scanner
	handler  slog.Handler
	dataset  string
	output   bytes.Buffer
}

// line records the all-detector findings digest, requires each single-kind
// scanner to agree with the all-detector scan, counts every configuration and
// samples the line's findings.
func (c *lineCheck) line(r *result, text string) error {
	all := c.scanners["all"].ScanString(text)
	if err := c.encoder.Encode(all); err != nil {
		return err
	}
	for kind, scanner := range c.singles {
		individual := scanner.ScanString(text)
		selected := slices.DeleteFunc(slices.Clone(all), func(f embargo.Finding) bool { return f.Kind != kind })
		if !slices.Equal(individual, selected) {
			return fmt.Errorf("single/all mismatch: %s line %d kind %s", c.dataset, r.Lines, kind)
		}
	}
	for name, scanner := range c.scanners {
		if err := c.configuration(r, name, scanner, text, all); err != nil {
			return err
		}
	}
	for _, f := range all {
		sampleFinding(r.Samples, c.dataset, r.Lines, text, f)
	}
	return nil
}

// configuration counts one scanner configuration's findings and, for the
// default policy, compares them with the message the slog handler wrote.
func (c *lineCheck) configuration(r *result, name string, scanner *embargo.Scanner, text string, all []embargo.Finding) error {
	findings := all
	if name != "all" {
		findings = scanner.ScanString(text)
	}
	for _, f := range findings {
		r.Counts[name][f.Kind]++
		if samples, ok := r.ThresholdSamples[name]; ok {
			sampleFinding(samples, c.dataset, r.Lines, text, f)
		}
	}
	if name != "default" {
		return nil
	}
	return c.handlerMessage(r.Lines, text, findings)
}

// handlerMessage requires the actual handler's message to equal Mask applied
// to the default scanner's findings.
func (c *lineCheck) handlerMessage(line int, text string, findings []embargo.Finding) error {
	c.output.Reset()
	record := slog.NewRecord(time.Time{}, slog.LevelInfo, text, 0)
	if err := c.handler.Handle(context.Background(), record); err != nil {
		return err
	}
	var decoded struct {
		Msg string `json:"msg"`
	}
	if err := json.Unmarshal(c.output.Bytes(), &decoded); err != nil {
		return err
	}
	if decoded.Msg != string([]rune(embargo.Mask(text, findings))) {
		return fmt.Errorf("handler mismatch: %s line %d", c.dataset, line)
	}
	return nil
}

func sampleFinding(samples map[embargo.Kind][]sample, dataset string, line int, text string, f embargo.Finding) {
	id := fmt.Sprintf("%s:%d:%s:%d:%d", dataset, line, f.Kind, f.Start, f.End)
	sum := sha256.Sum256([]byte(id))
	pick := sample{ID: hex.EncodeToString(sum[:]), Line: line, Finding: f, Text: text, Value: text[f.Start:f.End]}
	values := samples[f.Kind]
	const sampleSize = 40
	if len(values) == sampleSize && pick.ID >= values[len(values)-1].ID {
		return
	}
	values = append(values, pick)
	slices.SortFunc(values, func(a, b sample) int { return strings.Compare(a.ID, b.ID) })
	if len(values) > sampleSize {
		values = values[:sampleSize]
	}
	samples[f.Kind] = values
}
