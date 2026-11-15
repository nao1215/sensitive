package embargo_test

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/nao1215/embargo"
)

func Example() {
	scanner := embargo.NewScanner(embargo.WithPAN(), embargo.WithEmail())
	text := "user tanaka@example.com paid with 4532015112830366"
	for _, f := range scanner.ScanString(text) {
		fmt.Printf("%s: %s (%.2f)\n", f.DetectorName, f.RawValue, f.Confidence)
	}
	// Output:
	// pan: 4532015112830366 (1.00)
	// email: tanaka@example.com (1.00)
}

func ExampleNewScanner() {
	text := "tanaka@example.com 4532015112830366 from 192.0.2.1"
	for _, config := range []struct {
		name string
		opts []embargo.Option
	}{
		{"no options", nil},
		{"selected", []embargo.Option{embargo.WithPAN(), embargo.WithEmail()}},
		{"all built-ins", []embargo.Option{embargo.WithAll()}},
	} {
		scanner := embargo.NewScanner(config.opts...)
		fmt.Printf("%s: %d findings\n", config.name, len(scanner.ScanString(text)))
	}
	// Output:
	// no options: 0 findings
	// selected: 2 findings
	// all built-ins: 3 findings
}

func ExampleNewScanner_options() {
	// Keep overlapping candidates and process them in input order.
	custom := newPattern("reference", regexp.MustCompile(`REF-\d{4}`), nil, 0.5)
	scanner := embargo.NewScanner(
		embargo.WithEmail(),
		embargo.WithDetector(custom),
		embargo.WithoutDedup(),
		embargo.WithSortByPosition(),
	)
	for _, f := range scanner.ScanString("REF-1234@example.com then admin@example.com") {
		fmt.Printf("%s [%d:%d] %.1f\n", f.DetectorName, f.Start, f.End, f.Confidence)
	}
	// Output:
	// email [0:20] 1.0
	// reference [0:8] 0.5
	// email [26:43] 1.0
}

func ExampleScanner_Scan() {
	scanner := embargo.NewScanner(embargo.WithPAN())
	data := []byte("カード: 4532-0151-1283-0366")
	for _, f := range scanner.Scan(data) {
		fmt.Printf("%s [%d:%d]: %s\n", f.DetectorName, f.Start, f.End, data[f.Start:f.End])
	}
	// Output:
	// pan [11:30]: 4532-0151-1283-0366
}

func ExampleScanner_ScanString() {
	scanner := embargo.NewScanner(embargo.WithEmail())
	findings := scanner.ScanString("contact admin@example.com for support")
	fmt.Printf("found %d email(s)\n", len(findings))
	for _, f := range findings {
		fmt.Println(f.RawValue)
	}
	// Output:
	// found 1 email(s)
	// admin@example.com
}

func ExampleScanner_ScanReader() {
	scanner := embargo.NewScanner(embargo.WithEmail())
	reader := strings.NewReader("safe line\nadmin@example.com\n")
	findings, err := scanner.ScanReader(reader)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	for _, f := range findings {
		fmt.Printf("%s [%d:%d]\n", f.RawValue, f.Start, f.End)
	}
	// Output:
	// admin@example.com [10:27]
}

func ExampleScanner_ScanLines() {
	scanner := embargo.NewScanner(embargo.WithEmail())
	input := "safe line\nadmin@example.com\n"
	err := scanner.ScanLines(strings.NewReader(input), func(n int, line []byte, findings []embargo.Finding) {
		for _, f := range findings {
			fmt.Printf("line %d [%d:%d]: %s\n", n, f.Start, f.End, line[f.Start:f.End])
		}
	})
	if err != nil {
		fmt.Println("error:", err)
	}
	// Output:
	// line 2 [0:17]: admin@example.com
}

func ExampleWithMinConfidence() {
	text := "user tanaka@example.com bank account 12345678"
	for _, threshold := range []float64{0.4, 0.8} {
		scanner := embargo.NewScanner(
			embargo.WithEmail(), embargo.WithBankAccount(),
			embargo.WithMinConfidence(threshold),
		)
		fmt.Printf("threshold %.1f: %d findings\n", threshold, len(scanner.ScanString(text)))
	}
	// Output:
	// threshold 0.4: 2 findings
	// threshold 0.8: 1 findings
}

func ExampleWithDetector() {
	ticket := newPattern(
		"ticket_id", regexp.MustCompile(`TICKET-\d{4}`),
		[][]byte{[]byte("TICKET-")}, 0.9,
	)
	scanner := embargo.NewScanner(embargo.WithDetector(ticket))
	for _, f := range scanner.ScanString("see TICKET-4321 for details") {
		fmt.Printf("%s: %s (%.1f)\n", f.DetectorName, f.RawValue, f.Confidence)
	}
	// Output:
	// ticket_id: TICKET-4321 (0.9)
}

// pattern implements the public custom-detector contract.
type pattern struct {
	name       embargo.DetectorName
	expression *regexp.Regexp
	hints      [][]byte
	confidence float64
}

func newPattern(name embargo.DetectorName, expression *regexp.Regexp, hints [][]byte, confidence float64) *pattern {
	return &pattern{name: name, expression: expression, hints: hints, confidence: confidence}
}
func (p *pattern) Name() embargo.DetectorName { return p.name }
func (p *pattern) Hints() [][]byte            { return p.hints }
func (p *pattern) Scan(data []byte) []embargo.Finding {
	matches := p.expression.FindAllIndex(data, -1)
	findings := make([]embargo.Finding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, embargo.Finding{DetectorName: p.name, Start: match[0], End: match[1], RawValue: string(data[match[0]:match[1]]), Confidence: p.confidence})
	}
	return findings
}
