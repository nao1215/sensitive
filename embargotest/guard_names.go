package embargotest

import (
	"bytes"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nao1215/embargo"
)

type guardWrite struct{ start, end, stdout int }

func guardLeaks(data []byte, policy *Recorder) ([]embargo.Finding, bool) {
	findings, failed := policy.scanFindings(data)
	for _, needle := range policy.needles {
		for offset := 0; len(needle) > 0 && offset < len(data); {
			index := bytes.Index(data[offset:], needle)
			if index < 0 {
				break
			}
			start := offset + index
			findings = append(findings, embargo.Finding{Start: start, End: start + len(needle)})
			offset = start + len(needle)
		}
	}
	return findings, failed
}

// Attribution uses observed pipe order; it cannot establish which parallel test wrote a byte.
func guardTests(capture *guardCapture, stream int, leaks []embargo.Finding, policy *Recorder) string {
	positions := make([]int, 0, len(leaks))
	if stream == 0 {
		for _, f := range leaks {
			positions = append(positions, f.Start)
		}
	} else {
		for _, write := range capture.stderrWrites {
			for _, f := range leaks {
				if write.start < f.End && f.Start < write.end {
					positions = append(positions, write.stdout)
					break
				}
			}
		}
	}
	slices.Sort(positions)
	active := map[string]bool{}
	selected := map[string]bool{}
	data := capture.data[0]
	offset := 0
	for _, position := range positions {
		for offset < len(data) {
			end := bytes.IndexByte(data[offset:], '\n')
			if end < 0 || offset+end >= position {
				break
			}
			guardFrame(string(bytes.TrimPrefix(data[offset:offset+end], []byte{0x16})), active)
			offset += end + 1
		}
		for name := range active {
			selected[guardSafeName(name, policy)] = true
		}
	}
	names := make([]string, 0, len(selected))
	for name := range selected {
		names = append(names, name)
	}
	slices.Sort(names)
	if len(names) == 0 {
		return "[unavailable]"
	}
	return strings.Join(names, ", ")
}

func guardFrame(line string, active map[string]bool) {
	for _, prefix := range []string{"=== RUN   ", "=== CONT  "} {
		if name, ok := strings.CutPrefix(line, prefix); ok {
			active[name] = true
			return
		}
	}
	if name, ok := strings.CutPrefix(line, "=== PAUSE "); ok {
		delete(active, name)
		return
	}
	line = strings.TrimLeft(line, " \t")
	for _, prefix := range []string{"--- PASS: ", "--- FAIL: ", "--- SKIP: "} {
		if rest, ok := strings.CutPrefix(line, prefix); ok {
			name, _, _ := strings.Cut(rest, " (")
			delete(active, name)
			return
		}
	}
}

func guardSafeName(name string, policy *Recorder) string {
	const placeholder = "[redacted test name]"
	data := []byte(name)
	if containsCanary(data, policy.needles) {
		return placeholder
	}
	found, failed := policy.scan(data)
	if found || failed {
		return placeholder
	}
	if name == "" || len(name) > 120 || !utf8.ValidString(name) {
		return placeholder
	}
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("_/-.=, ", r) {
			return placeholder
		}
	}
	return name
}
