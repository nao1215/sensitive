package embargo

import (
	"bufio"
	"io"
	"slices"

	"github.com/nao1215/embargo/internal/detect"
)

// ScanLines calls fn synchronously for lines containing findings, using 1-based
// line numbers and line-relative byte offsets. Each line excludes its LF or
// CRLF terminator and is a copy that fn may retain. A selected PEM finding
// carries through its matching END line or end of input;
// subsequent key-material lines receive line-relative PEM findings.
//
// The buffer limit is 1 MiB including delimiter space; longer lines return
// [bufio.ErrTooLong]. Read errors are returned after any callbacks already made.
func (s *Scanner) ScanLines(r io.Reader, fn func(lineNum int, line []byte, findings []Finding)) error {
	if !s.initialized {
		return NewScanner().ScanLines(r, fn)
	}
	sc := bufio.NewScanner(r)
	//nolint:mnd // The documented buffer limits are 64 KiB and 1 MiB.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	var label []byte
	for sc.Scan() {
		lineNum++
		raw := sc.Bytes()
		view := detect.NewView(raw)
		findings := s.scanInput(view, nil)
		covered := 0
		if len(label) > 0 {
			end, complete := detect.PEMFooter(view.Data, 0, label)
			if complete {
				label = nil
			}
			end = view.Original(end)
			covered = end
			if end > 0 {
				//nolint:mnd // A continuation has the documented PEM header confidence.
				findings = append(findings, Finding{Kind: KindPrivateKeyPEM, Start: 0, End: end, Confidence: 0.99})
			}
		}
		if len(label) == 0 {
			label = pemLineLabel(view, findings, covered)
		}
		if len(findings) > 0 {
			// Copy raw so the callback can safely retain the slice;
			// bufio.Scanner reuses its internal buffer on the next Scan.
			line := make([]byte, len(raw))
			copy(line, raw)
			fn(lineNum, line, findings)
		}
	}
	return sc.Err()
}

func pemLineLabel(view detect.View, findings []Finding, covered int) []byte {
	data, positions := view.Data, view.Positions
	for _, f := range findings {
		if f.Kind != KindPrivateKeyPEM || f.Start < covered {
			continue
		}
		start := f.Start
		if positions != nil {
			// The mapping is monotonic and includes the end sentinel.
			var found bool
			start, found = slices.BinarySearch(positions, f.Start)
			if !found {
				continue
			}
		}
		label, end := detect.PEMHeader(data, start)
		if label == nil {
			continue
		}
		if _, complete := detect.PEMFooter(data, end, label); !complete {
			// Only a continuing block retains a label across scanner buffer reuse.
			return slices.Clone(label)
		}
	}
	return nil
}
