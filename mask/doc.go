// Package mask replaces sensitive findings using per-detector [Mask] or uniform [MaskAll] strategies. The sensitive package performs detection; callers may also use its findings with their own masking logic.
//
// [Strategy] constants document what remains visible, and the examples show their output. Partial masking and the short [Hash] fingerprint retain information; use [Redact] when the whole matched value should be hidden.
package mask
