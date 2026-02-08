// Package sensitive provides a high-performance, rule-based sensitive data
// detection library for Go. It scans text for credit card numbers (PAN),
// email addresses, phone numbers, Japanese My Number, and other confidential
// information, returning the position, type, and confidence level of each finding.
//
// Detection is the core focus. Masking is optional and provided as a thin helper
// in the mask sub-package. Users can implement their own masking logic using
// the detection results.
//
// # Architecture
//
// The library uses a multi-stage filtering pipeline to minimize scan cost:
//
//  1. Hint-based pre-filter: Each Detector provides hint byte sequences.
//     bytes.Contains (SIMD-optimized in Go runtime) quickly eliminates
//     lines that cannot possibly contain a match (~15ns per line).
//  2. Detector.Scan: Only called on data that passes the hint filter.
//     Uses dedicated parsers and domain rule validation (BIN check, Luhn,
//     check digits, etc.) rather than regular expressions.
//  3. Result merging: Overlapping findings are deduplicated and sorted
//     by confidence.
//
// # Usage
//
//	scanner := sensitive.NewScanner(sensitive.WithAll())
//	findings := scanner.ScanString("card is 4532-0151-1283-0366")
//	for _, f := range findings {
//	    fmt.Printf("Found %s at [%d:%d] confidence=%.2f\n",
//	        f.DetectorName, f.Start, f.End, f.Confidence)
//	}
package sensitive
