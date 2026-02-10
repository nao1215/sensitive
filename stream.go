package sensitive

import (
	"bufio"
	"io"
)

// ScanReader reads all data from r and scans it for sensitive data.
// This is a convenience method for cases where the full content fits in memory.
// For large inputs or streaming use cases, prefer [Scanner.ScanLines].
//
//	f, _ := os.Open("access.log")
//	defer f.Close()
//	findings, err := scanner.ScanReader(f)
func (s *Scanner) ScanReader(r io.Reader) ([]Finding, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return s.Scan(data), nil
}

// ScanLines reads from r line by line and calls fn for each line that
// contains at least one finding. This is the recommended API for scanning
// log files and other line-oriented text streams, as it processes data
// incrementally without loading the entire input into memory.
//
// lineNum is 1-based. The line parameter is a copy of the raw line bytes
// (without the trailing newline), safe to retain after fn returns.
// findings contains all detections for that line.
//
// fn is only called for lines that contain findings. Lines with no
// sensitive data are silently skipped.
//
// The internal buffer starts at 64 KB and grows up to 1 MB per line.
// Lines exceeding 1 MB cause ScanLines to return [bufio.ErrTooLong].
// If you need to handle longer lines, use [Scanner.ScanReader] instead
// (which loads the entire input into memory).
//
// Returns the first error encountered while reading from r, or nil
// if the entire input was processed successfully.
//
//	f, _ := os.Open("access.log")
//	defer f.Close()
//	err := scanner.ScanLines(f, func(lineNum int, line []byte, findings []Finding) {
//	    fmt.Printf("line %d: found %d sensitive values\n", lineNum, len(findings))
//	})
func (s *Scanner) ScanLines(r io.Reader, fn func(lineNum int, line []byte, findings []Finding)) error {
	sc := bufio.NewScanner(r)
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
