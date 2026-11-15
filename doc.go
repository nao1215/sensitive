// Package embargo detects and masks personal data, payment data and credentials.
// NewScanner enables all built-ins, including IP addresses and context-based detectors;
// use WithKinds to narrow selection. Findings contain byte positions, never raw values.
// Mask replaces covered spans with [REDACTED]; MaskFunc permits caller-defined replacements.
package embargo
