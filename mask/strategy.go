package mask

// Strategy selects a replacement for a finding's RawValue; unknown values leave it unchanged. Character counts are Unicode rune counts.
type Strategy int

const (
	// Redact replaces every character with an asterisk.
	Redact Strategy = iota
	// Last4 preserves the last four characters; values of four or fewer characters are unchanged.
	Last4
	// First1Last4 preserves the first and last four characters; values of five or fewer characters are unchanged.
	First1Last4
	// Partial preserves an email's first local character and domain; a one-character local part is unchanged. Other values use Last4.
	Partial
	// Hash replaces the value with the first eight lowercase hex digits of its SHA-256 hash.
	Hash
)
