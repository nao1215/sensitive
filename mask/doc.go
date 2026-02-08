// Package mask provides optional masking helpers for the sensitive library.
//
// This package is intentionally thin — detection is the core focus of the
// sensitive library, and users are encouraged to implement their own masking
// logic using the detection results ([sensitive.Finding]). This package serves
// as a convenience layer for common masking patterns.
//
// # Available Strategies
//
//   - [Redact]: Complete redaction, replacing the value with asterisks ("********")
//   - [Last4]: Show only the last 4 characters ("****1234")
//   - [First1Last4]: Show first and last characters ("4***1234")
//   - [Partial]: Partial display suitable for emails ("t***@example.com")
//   - [Hash]: SHA-256 hash, first 8 hex characters ("a8f5f167")
//
// # Usage
//
//	scanner := sensitive.NewScanner(sensitive.WithAll())
//	findings := scanner.ScanString(text)
//	masked := mask.Mask(text, findings, map[string]mask.Strategy{
//	    "pan":   mask.Last4,
//	    "email": mask.Partial,
//	})
package mask
