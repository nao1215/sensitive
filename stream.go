package embargo

import (
	"bufio"
	"bytes"
	"io"
	"strings"
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
	sc := bufio.NewScanner(r)
	//nolint:mnd // The documented buffer limits are 64 KiB and 1 MiB.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	var footer []byte
	for sc.Scan() {
		lineNum++
		raw := sc.Bytes()
		findings := s.Scan(raw)
		covered := 0
		if len(footer) > 0 {
			end := len(raw)
			if at := bytes.Index(raw, footer); at >= 0 && at < end {
				end = at + len(footer)
				footer = nil
			}
			covered = end
			if end > 0 {
				//nolint:mnd // A continuation has the documented PEM header confidence.
				findings = append(findings, Finding{Kind: KindPrivateKeyPEM, Start: 0, End: end, Confidence: 0.99})
			}
		}
		if len(footer) == 0 {
			footer = pemLineFooter(raw, findings, covered)
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

func pemLineFooter(raw []byte, findings []Finding, covered int) []byte {
	for _, f := range findings {
		if f.Kind != KindPrivateKeyPEM || f.Start < covered {
			continue
		}
		const opener = "-----BEGIN "
		tail := raw[f.Start:f.End]
		if !bytes.HasPrefix(tail, []byte(opener)) {
			continue
		}
		if end := bytes.Index(tail[len(opener):], []byte("-----")); end >= 0 {
			label := string(tail[len(opener) : len(opener)+end])
			if strings.HasSuffix(label, "PRIVATE KEY") {
				next := []byte("-----END " + label + "-----")
				if !bytes.Contains(tail, next) {
					return next
				}
			}
		}
	}
	return nil
}
