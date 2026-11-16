package embargo

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/nao1215/embargo/internal/ascii"
)

// The pre-optimization dispatch loop remains test-only, using the same detectors
// so that deliberate accuracy changes do not masquerade as optimization drift.
const documentedEmail = "alice@example.com"

func referenceScan(s *Scanner, data []byte) []Finding {
	original := data
	data, positions := decodePercent(data)
	var out []Finding
	var folded []byte
	var ready bool
	for i, d := range s.detectors {
		if !matchesAnyHint(s.hintCache[i], data, &folded, &ready) {
			continue
		}
		input := data
		if Kind(d.Name()) == KindCredential {
			input = original
		}
		for _, f := range d.Scan(input) {
			if positions != nil && Kind(d.Name()) != KindCredential {
				f.Start, f.End = positions[f.Start], positions[f.End]
			}
			if f.Confidence >= s.minConfidence {
				out = append(out, Finding{Kind: Kind(f.DetectorName), Start: f.Start, End: f.End, Confidence: f.Confidence})
			}
		}
	}
	slices.SortStableFunc(out, compareFindings)
	return out
}

func TestDispatchDifferential(t *testing.T) {
	t.Parallel()
	// #nosec G404 -- Fixed seed for reproducible synthetic tests.
	rng := rand.New(rand.NewPCG(72, 54))
	parts := []string{"foo", "@", "ABC", "0123456789", " ", "\n", "銀行", "４２４２", "expiry 12/29", "CVV 123", "a+b@example.com", "SWIFT: DEUTDEFF", "%20", "bank account 12345678", "4242424242424242", "090-1234-5678", "ghp_", "\xff", "sort code 40-12-36"}
	for _, s := range []*Scanner{NewScanner(), NewScanner(WithKinds(KindEmail)), NewScanner(WithMinConfidence(.7)), NewScanner(WithKinds())} {
		for i := range 3000 {
			var data []byte
			for range rng.IntN(15) {
				data = append(data, parts[rng.IntN(len(parts))]...)
			}
			if i%3 == 0 {
				data = append(data, byte(rng.IntN(256))) // #nosec G115 -- IntN is bounded to a byte.
			}
			got, want := s.Scan(data), referenceScan(s, data)
			if !slices.Equal(got, want) {
				t.Fatalf("input %q\ngot %+v\nwant %+v", data, got, want)
			}
		}
	}
}

//nolint:paralleltest // AllocsPerRun changes GOMAXPROCS while measuring.
func TestCleanScanAllocationBudget(t *testing.T) {
	s := NewScanner()
	data := []byte("worker completed request reference=example\n")
	if got := testing.AllocsPerRun(100, func() { s.Scan(data) }); got != 0 {
		t.Fatalf("clean input allocated %.0f times", got)
	}
}

func TestDispatchExhaustiveNumericAndTerminalHints(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		kind  Kind
		input string
		end   int
	}{
		{KindMyNumber, "111111111118", 12},
		{KindABARouting, "111111118", 9},
		{KindCVV, "123 CVV", 3},
		{KindBankAccount, "12345678 bank account", 8},
		{KindACHTrace, "021000021123456 ACH trace", 15},
	} {
		for _, scanner := range []*Scanner{NewScanner(WithKinds(tc.kind)), NewScanner(WithAll())} {
			got := slices.DeleteFunc(scanner.ScanString(tc.input), func(f Finding) bool { return f.Kind != tc.kind })
			if len(got) != 1 || got[0].Kind != tc.kind || got[0].Start != 0 || got[0].End != tc.end {
				t.Fatal(tc.kind, got)
			}
		}
	}
}

// The README states how many detectors exist and how many NewScanner runs; a new
// kind must update that sentence in the same change.
func TestReadmeDetectorCounts(t *testing.T) {
	t.Parallel()
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%d built-in detectors (%d run by default)", len(builtins()), len(NewScanner().detectors))
	if !strings.Contains(string(readme), want) {
		t.Fatalf("README must say %q", want)
	}
	if overview := fmt.Sprintf("[%d built-in detectors](", len(builtins())); !strings.Contains(string(readme), overview) {
		t.Fatalf("README overview must link %q", overview)
	}
	_, table, found := strings.Cut(string(readme), "| Group | Detectors | What is detected |\n|---|---:|---|\n")
	if !found {
		t.Fatal("README detector group table not found")
	}
	total := 0
	for row := range strings.Lines(table) {
		cells := strings.Split(row, "|")
		if len(cells) < 4 {
			break
		}
		n, err := strconv.Atoi(strings.TrimSpace(cells[2]))
		if err != nil {
			t.Fatalf("README group row %q: %v", row, err)
		}
		total += n
	}
	if total != len(builtins()) {
		t.Fatalf("README detector groups add up to %d, want %d", total, len(builtins()))
	}
}

type candidateNode struct {
	next   [256]int
	output uint32
}

type candidateLexer struct {
	nodes                   []candidateNode
	numeric, token, hex, at uint32
}

type candidateSpan struct {
	start, end int
	kinds      uint32
}

func newCandidateLexer(s *Scanner) *candidateLexer {
	lexer := &candidateLexer{nodes: make([]candidateNode, 1)}
	for i, d := range s.detectors {
		mask := uint32(1) << i
		switch Kind(d.Name()) { //nolint:exhaustive // Other detectors receive candidates from their mandatory hints.
		case KindPAN, KindMyNumber, KindABARouting, KindUKSortCode, KindJPPhone:
			lexer.numeric |= mask
		case KindHighEntropy, KindSWIFTBIC, KindBTC:
			lexer.token |= mask
		case KindIBAN:
			lexer.numeric |= mask
			lexer.token |= mask
		case KindIPAddr, KindETH:
			lexer.hex |= mask
		case KindEmail, KindCredential:
			lexer.at |= mask
		}
		for _, entry := range s.hintCache[i] {
			state := 0
			for _, b := range entry.lowered {
				if lexer.nodes[state].next[b] == 0 {
					lexer.nodes[state].next[b] = len(lexer.nodes)
					lexer.nodes = append(lexer.nodes, candidateNode{})
				}
				state = lexer.nodes[state].next[b]
			}
			lexer.nodes[state].output |= mask
		}
	}
	// Complete the trie with failure transitions in breadth-first order.
	failure := make([]int, len(lexer.nodes))
	var queue []int
	for _, child := range &lexer.nodes[0].next {
		if child != 0 {
			queue = append(queue, child)
		}
	}
	for head := 0; head < len(queue); head++ {
		state := queue[head]
		for b, child := range &lexer.nodes[state].next {
			if child == 0 {
				lexer.nodes[state].next[b] = lexer.nodes[failure[state]].next[b]
				continue
			}
			failure[child] = lexer.nodes[failure[state]].next[b]
			lexer.nodes[child].output |= lexer.nodes[failure[child]].output
			queue = append(queue, child)
		}
	}
	return lexer
}

//nolint:gocognit,gocyclo // Keep the three concurrent character-class runs in one pass for this experiment.
func (lexer *candidateLexer) lex(data []byte) []candidateSpan {
	var spans []candidateSpan
	starts := [3]int{-1, -1, -1}
	state := 0
	for i := 0; i <= len(data); i++ {
		var b byte
		if i < len(data) {
			b = data[i]
		}
		digit := b >= '0' && b <= '9'
		letter := b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
		classes := [3]bool{
			i < len(data) && (digit || b == '-' || b == ' ' || b == '(' || b == ')' || b >= 0x80),
			i < len(data) && (digit || letter || b == '_' || b == '-' || b == '+' || b == '/'),
			i < len(data) && (digit || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'),
		}
		for class, active := range classes {
			if active && starts[class] < 0 {
				starts[class] = i
			}
			if active || starts[class] < 0 {
				continue
			}
			start := starts[class]
			starts[class] = -1
			mask := lexer.numeric
			if class == 1 {
				mask = lexer.token
				length := i - start
				if length != 8 && length != 11 && length < 15 {
					continue
				}
			} else if class == 2 {
				mask = lexer.hex
				if i-start < 4 {
					continue
				}
			}
			spans = append(spans, candidateSpan{start: start, end: i, kinds: mask})
		}
		if i == len(data) {
			break
		}
		if b == '@' {
			spans = append(spans, candidateSpan{start: i, end: i + 1, kinds: lexer.at})
		}
		state = lexer.nodes[state].next[ascii.ToLower(b)]
		if mask := lexer.nodes[state].output; mask != 0 {
			spans = append(spans, candidateSpan{start: i, end: i + 1, kinds: mask})
		}
	}
	slices.SortFunc(spans, func(a, b candidateSpan) int { return a.start - b.start })
	return spans
}

func candidateScan(s *Scanner, lexer *candidateLexer, original []byte) []Finding {
	data, positions := decodePercent(original)
	spans := lexer.lex(data)
	var out []Finding
	for i, d := range s.detectors {
		input := data
		candidates := spans
		if Kind(d.Name()) == KindCredential && positions != nil {
			input = original
			candidates = lexer.lex(original)
		}
		var windows []candidateSpan
		for _, span := range candidates {
			if span.kinds&(1<<i) == 0 {
				continue
			}
			window := candidateSpan{start: max(0, span.start-64), end: min(len(input), span.end+256)}
			if len(windows) > 0 && window.start <= windows[len(windows)-1].end {
				windows[len(windows)-1].end = max(windows[len(windows)-1].end, window.end)
			} else {
				windows = append(windows, window)
			}
		}
		for _, window := range windows {
			for _, f := range d.Scan(input[window.start:window.end]) {
				start, end := f.Start+window.start, f.End+window.start
				if positions != nil && Kind(d.Name()) != KindCredential {
					start, end = positions[start], positions[end]
				}
				if f.Confidence >= s.minConfidence {
					out = append(out, Finding{Kind: Kind(f.DetectorName), Start: start, End: end, Confidence: f.Confidence})
				}
			}
		}
	}
	slices.SortStableFunc(out, compareFindings)
	return out
}

func TestCandidateLexer(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithAll())
	lexer := newCandidateLexer(scanner)
	for _, text := range []string{"worker completed request reference=example", "4111 1111 1111 1111", documentedEmail, "github_pat_" + strings.Repeat("A", 82), "password=example-value"} {
		if got, want := candidateScan(scanner, lexer, []byte(text)), scanner.ScanString(text); !slices.Equal(got, want) {
			t.Fatalf("candidate smoke mismatch for %q: %v versus %v", text, got, want)
		}
	}
}

func experimentTexts(b *testing.B) (clean, dirtyText []byte) {
	b.Helper()
	data, err := os.ReadFile("testdata/recall.json")
	if err != nil {
		b.Fatal(err)
	}
	var samples []struct {
		Text     string   `json:"text"`
		Detector string   `json:"detector"`
		Parts    []string `json:"parts"`
		Positive bool     `json:"positive"`
	}
	if err := json.Unmarshal(data, &samples); err != nil {
		b.Fatal(err)
	}
	dirty := map[string]string{}
	for _, sample := range samples {
		if sample.Positive && dirty[sample.Detector] == "" {
			dirty[sample.Detector] = sample.Text + strings.Join(sample.Parts, "")
		}
	}
	names := make([]string, 0, len(dirty))
	for name := range dirty {
		names = append(names, name)
	}
	slices.Sort(names)
	all := make([]string, 0, len(names))
	for _, name := range names {
		all = append(all, dirty[name])
	}
	return bytes.Repeat([]byte("worker completed request reference=example\n"), 64), bytes.Repeat([]byte(strings.Join(all, "\n")+"\n"), 64)
}

//nolint:goconst // State names match the published benchmark axes.
func BenchmarkCandidateExperiment(b *testing.B) {
	clean, dirty := experimentTexts(b)
	scanner := NewScanner(WithAll())
	lexer := newCandidateLexer(scanner)
	for _, state := range []string{"clean", "dirty"} {
		input := clean
		if state == "dirty" {
			input = dirty
		}
		for _, mode := range []string{"production", "candidate"} {
			b.Run(state+"/"+mode, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(input)))
				for b.Loop() {
					if mode == "candidate" {
						candidateScan(scanner, lexer, input)
					} else {
						scanner.Scan(input)
					}
				}
			})
		}
	}
}

// TestCandidateExperimentGate records mismatches rather than accepting drift in
// production. No candidate code is reachable from a library build.
//
//nolint:gocognit,nestif // One experiment audits generated fixtures and cached source logs using the same comparator.
func TestCandidateExperimentGate(t *testing.T) {
	t.Parallel()
	output := os.Getenv("EMBARGO_CANDIDATE_REPORT")
	if output == "" {
		t.Skip("set EMBARGO_CANDIDATE_REPORT to evaluate the experiment")
	}
	scanner := NewScanner(WithAll())
	lexer := newCandidateLexer(scanner)
	type mismatch struct {
		Source     string    `json:"source"`
		Production []Finding `json:"production"`
		Candidate  []Finding `json:"candidate"`
		Line       int       `json:"line"`
	}
	type count struct {
		Inputs    int `json:"inputs"`
		Different int `json:"different"`
	}
	report := struct {
		Counts   map[string]*count `json:"counts"`
		Examples []mismatch        `json:"examples"`
	}{Counts: map[string]*count{}}
	check := func(source string, line int, text []byte) {
		c := report.Counts[source]
		if c == nil {
			c = &count{}
			report.Counts[source] = c
		}
		c.Inputs++
		got, want := candidateScan(scanner, lexer, text), scanner.Scan(text)
		if !slices.Equal(got, want) {
			c.Different++
			if c.Different <= 2 {
				report.Examples = append(report.Examples, mismatch{Source: source, Line: line, Production: want, Candidate: got})
			}
		}
	}
	for i, text := range []string{
		"password=" + strings.Repeat("fakevalue", 128),
		"-----BEGIN PRIVATE KEY-----\n" + strings.Repeat("ZmFrZQ==\n", 100) + "-----END PRIVATE KEY-----",
		"sk-proj-" + strings.Repeat("Fake0", 100),
	} {
		check("long-candidate-boundaries", i+1, []byte(text))
	}
	for _, path := range []string{"accuracy_generated.jsonl", "accuracy_generated_controls.jsonl", "accuracy_held_generated.jsonl", "accuracy_held_generated_controls.jsonl", "credentials-development.jsonl", "credentials-held.jsonl"} {
		// #nosec G304 -- The file comes from the fixed list of local generated fixtures.
		file, err := os.Open(filepath.Join("tests", "testdata", path))
		if err != nil {
			t.Fatal(err)
		}
		lines := bufio.NewScanner(file)
		n := 0
		for lines.Scan() {
			n++
			var item struct {
				Text string `json:"text"`
			}
			if err := json.Unmarshal(lines.Bytes(), &item); err != nil {
				t.Fatal(err)
			}
			check(path, n, []byte(item.Text))
		}
		if err := lines.Err(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if cache := os.Getenv("EMBARGO_LOG_CACHE"); cache != "" {
		data, err := os.ReadFile("doc/real-logs-manifest.json")
		if err != nil {
			t.Fatal(err)
		}
		var manifest struct {
			Datasets []struct {
				Name string `json:"name"`
				Path string `json:"path"`
			} `json:"datasets"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			t.Fatal(err)
		}
		for _, dataset := range manifest.Datasets {
			// #nosec G304 G703 -- Explicit opt-in experiment reads the operator-provided cache and committed manifest.
			file, err := os.Open(filepath.Join(cache, dataset.Path))
			if err != nil {
				t.Fatal(err)
			}
			lines := bufio.NewScanner(file)
			lines.Buffer(make([]byte, 4096), 4<<20)
			n := 0
			for lines.Scan() {
				n++
				check(dataset.Name, n, lines.Bytes())
			}
			if err := lines.Err(); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	encoded, err := json.MarshalIndent(report, "", "  ") //nolint:musttag // Findings retain their existing exported field names in the experiment report.
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G703 -- Explicit local experiment output path; no public log text is written.
	if err := os.WriteFile(output, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkNarrowing(b *testing.B) {
	clean, dirty := experimentTexts(b)
	policies := []struct {
		option ScannerOption
		name   string
	}{
		{name: "all", option: WithAll()},
		{name: "kinds1", option: WithKinds(KindEmail)},
		{name: "kinds3", option: WithKinds(KindEmail, KindPAN, KindCredential)},
		{name: "kinds8", option: WithKinds(KindEmail, KindPAN, KindCredential, KindJPPhone, KindIPAddr, KindGitHubToken, KindServiceToken, KindPrivateKeyPEM)},
	}
	for _, policy := range policies {
		scanner := NewScanner(policy.option)
		for _, state := range []string{"clean", "dirty"} {
			input := clean
			if state == "dirty" {
				input = dirty
			}
			b.Run(policy.name+"/"+state, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(input)))
				for b.Loop() {
					scanner.Scan(input)
				}
			})
		}
	}
}

func TestBuiltInDispatchHintsAreNonempty(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithAll())
	for _, hints := range scanner.hintCache {
		for _, hint := range hints {
			if len(hint.lowered) == 0 {
				t.Fatal("empty built-in hint requires unconditional dispatch")
			}
		}
	}
}
