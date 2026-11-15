package embargo

import (
	"bufio"
	"io"
)

// ScanLines calls fn synchronously for each line containing findings, with 1-based line numbers and line-relative byte offsets. The line excludes its LF or CRLF terminator and is a copy that fn may retain.
//
// The buffer starts at 64 KiB and grows to 1 MiB, including space needed for the line terminator. A line that exceeds the buffer limit returns [bufio.ErrTooLong]; use an explicit bounded read and [Scanner.Scan] for longer lines. Read errors are returned after any callbacks already made.
func (s *Scanner) ScanLines(r io.Reader, fn func(lineNum int, line []byte, findings []Finding)) error {
	sc := bufio.NewScanner(r)
	//nolint:mnd // The documented buffer limits are 64 KiB and 1 MiB.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		raw := sc.Bytes()
		findings := s.Scan(raw)
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
