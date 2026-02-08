package mask

// Strategy defines the masking strategy to apply to a detected value.
type Strategy int

const (
	// Redact replaces the entire value with asterisks.
	// Example: "4532015112830366" → "****************"
	Redact Strategy = iota

	// Last4 shows only the last 4 characters, replacing the rest with asterisks.
	// Example: "4532015112830366" → "************0366"
	Last4

	// First1Last4 shows the first character and last 4 characters.
	// Example: "4532015112830366" → "4***********0366"
	First1Last4

	// Partial provides context-aware partial masking.
	// For email addresses: "tanaka@example.com" → "t*****@example.com"
	// For other values: behaves like Last4.
	Partial

	// Hash replaces the value with the first 8 hex characters of its SHA-256 hash.
	// Example: "4532015112830366" → "a8f5f167"
	Hash
)
