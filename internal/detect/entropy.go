package detect

import (
	"math"
	"strings"
)

// HighEntropy finds unlabelled 32..256 byte base64-like tokens with at least
// three character classes and Shannon entropy >=4.5 bits/byte. Confidence is
// only 0.3: random public IDs are indistinguishable from secrets without context.
// Hex hashes, UUIDs and tokens directly assigned to common ID labels are omitted.
type HighEntropy struct{}

// Name returns the high entropy family.
func (*HighEntropy) Name() DetectorName { return "high_entropy" }

// Hints returns nil because unprefixed tokens have no mandatory substring.
func (*HighEntropy) Hints() [][]byte { return nil }

// Scan returns uncertain high-entropy candidates, including public random IDs
// whose semantics cannot be inferred. A minimum confidence above 0.3 excludes them.
func (d *HighEntropy) Scan(data []byte) []Finding {
	var out []Finding
	for start := 0; start < len(data); {
		if !entropyByte(data[start]) {
			start++
			continue
		}
		end := start + 1
		for end < len(data) && entropyByte(data[end]) {
			end++
		}
		if entropyCandidate(data[start:end]) && !ordinaryIDContext(data, start) {
			//nolint:mnd // Uncontextualized entropy is deliberately below masking precision thresholds.
			out = append(out, Finding{DetectorName: d.Name(), Start: start, End: end, Confidence: 0.3, RawValue: string(data[start:end])})
		}
		start = end
	}
	return out
}

func entropyByte(b byte) bool { return tokenByte(b) || b == '+' || b == '/' }

func entropyCandidate(data []byte) bool {
	const minLength, maxLength, minEntropy = 32, 256, 4.5
	if len(data) < minLength || len(data) > maxLength {
		return false
	}
	var counts [256]int
	var lower, upper, digit, symbol bool
	for _, b := range data {
		counts[b]++
		switch {
		case b >= 'a' && b <= 'z':
			lower = true
		case b >= 'A' && b <= 'Z':
			upper = true
		case b >= '0' && b <= '9':
			digit = true
		default:
			symbol = true
		}
	}
	const minimumClasses = 3
	classes := 0
	for _, present := range []bool{lower, upper, digit, symbol} {
		if present {
			classes++
		}
	}
	if classes < minimumClasses {
		return false
	}
	score := 0.0
	for _, count := range &counts {
		if count != 0 {
			p := float64(count) / float64(len(data))
			score -= p * math.Log2(p)
		}
	}
	return score >= minEntropy
}

func ordinaryIDContext(data []byte, start int) bool {
	const contextBytes = 64
	before := strings.TrimSpace(string(data[max(0, start-contextBytes):start]))
	before = strings.TrimRight(before, "\"' ")
	if before == "" {
		return false
	}
	last := before[len(before)-1]
	if last != '=' && last != ':' {
		return false
	}
	key := NormalizeCredentialKey(string(assignmentKey([]byte(before), len(before)-1)))
	switch key {
	case "id", "requestid", "traceid", "spanid", "commit", "sha", "hash", "checksum", "uuid":
		return true
	}
	return false
}
