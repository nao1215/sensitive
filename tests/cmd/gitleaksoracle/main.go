// Command gitleaksoracle measures default-scanner coverage of the true-positive
// examples that the gitleaks rule generator validates. scripts/gitleaks_oracle.py
// generates those examples outside the repository; this command never stores them.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/nao1215/embargo"
)

// sample is one generated line with the secret that gitleaks extracted from it.
type sample struct {
	Rule   string `json:"rule"`
	Line   string `json:"line"`
	Secret string `json:"secret"`
}

// ruleResult counts examples whose extracted secret no longer appears after
// masking, separately for the generated line and for the bare secret.
type ruleResult struct {
	Rule        string `json:"rule"`
	Lines       int    `json:"lines"`
	MaskedLines int    `json:"masked_lines"`
	Secrets     int    `json:"secrets"`
	MaskedBare  int    `json:"masked_bare"`
}

// summary aggregates rules and examples; a rule is covered when every example is.
type summary struct {
	Rules             int          `json:"rules"`
	Lines             int          `json:"lines"`
	MaskedLines       int          `json:"masked_lines"`
	RulesAllLines     int          `json:"rules_all_lines"`
	Secrets           int          `json:"secrets"`
	MaskedBare        int          `json:"masked_bare"`
	RulesAllBare      int          `json:"rules_all_bare"`
	PerRule           []ruleResult `json:"per_rule"`
	BareContext       string       `json:"bare_context"`
}

// bareContext surrounds a bare secret with words that carry no credential key.
const bareContext = "event=%s status=failed"

func main() {
	samples := flag.String("samples", "", "JSON Lines file written by scripts/gitleaks_oracle.py")
	flag.Parse()
	if err := run(*samples, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path string, out io.Writer) error {
	if path == "" {
		return errors.New("--samples is required")
	}
	file, err := os.Open(path) // #nosec G304 -- The caller names a generated cache file.
	if err != nil {
		return err
	}
	defer file.Close()
	samples, err := readSamples(file)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(measure(embargo.NewScanner(), samples))
}

func readSamples(r io.Reader) ([]sample, error) {
	var samples []sample
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		var s sample
		if err := json.Unmarshal(scanner.Bytes(), &s); err != nil {
			return nil, fmt.Errorf("sample %d: %w", len(samples)+1, err)
		}
		if s.Rule == "" || s.Secret == "" || !strings.Contains(s.Line, s.Secret) {
			return nil, fmt.Errorf("sample %d: rule, line and a contained secret are required", len(samples)+1)
		}
		samples = append(samples, s)
	}
	return samples, scanner.Err()
}

// masked reports whether the secret is absent from the masked text.
func masked(scanner *embargo.Scanner, text, secret string) bool {
	return !strings.Contains(embargo.Mask(text, scanner.ScanString(text)), secret)
}

func measure(scanner *embargo.Scanner, samples []sample) summary {
	rules := map[string]*ruleResult{}
	bare := map[string]map[string]bool{}
	for _, s := range samples {
		r := rules[s.Rule]
		if r == nil {
			r = &ruleResult{Rule: s.Rule}
			rules[s.Rule] = r
			bare[s.Rule] = map[string]bool{}
		}
		r.Lines++
		if masked(scanner, s.Line, s.Secret) {
			r.MaskedLines++
		}
		if _, seen := bare[s.Rule][s.Secret]; !seen {
			bare[s.Rule][s.Secret] = masked(scanner, fmt.Sprintf(bareContext, s.Secret), s.Secret)
		}
	}
	result := summary{BareContext: bareContext}
	for _, r := range rules {
		for _, ok := range bare[r.Rule] {
			r.Secrets++
			if ok {
				r.MaskedBare++
			}
		}
		result.Rules++
		result.Lines += r.Lines
		result.MaskedLines += r.MaskedLines
		result.Secrets += r.Secrets
		result.MaskedBare += r.MaskedBare
		if r.MaskedLines == r.Lines {
			result.RulesAllLines++
		}
		if r.MaskedBare == r.Secrets {
			result.RulesAllBare++
		}
		result.PerRule = append(result.PerRule, *r)
	}
	slices.SortFunc(result.PerRule, func(a, b ruleResult) int { return strings.Compare(a.Rule, b.Rule) })
	return result
}
