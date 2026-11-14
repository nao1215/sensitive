package mask

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/nao1215/sensitive"
)

// Mask replaces findings in text using strategyMap; unmapped detector names remain unchanged. Findings must refer to text, with RawValue equal to text[Start:End]; the input slice is not modified.
//
// Invalid ranges (Start < 0, End > len(text), or Start >= End) are skipped. Replacements run right to left; a finding overlapping an already applied replacement is skipped, and equal-start overlaps have no guaranteed winner.
func Mask(text string, findings []sensitive.Finding, strategyMap map[sensitive.DetectorName]Strategy) string {
	if len(findings) == 0 {
		return text
	}

	// Sort findings by Start position descending so we can replace
	// from right to left without invalidating positions.
	sorted := make([]sensitive.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Start > sorted[j].Start
	})

	result := text
	// prevStart tracks the leftmost boundary of the last applied
	// replacement. Any finding whose End exceeds prevStart would
	// overlap with an already-replaced region and is skipped.
	prevStart := len(text)
	for _, f := range sorted {
		// Skip findings with out-of-range positions.
		if f.Start < 0 || f.End > len(text) || f.Start >= f.End {
			continue
		}
		// Skip findings that overlap with an already-applied replacement.
		if f.End > prevStart {
			continue
		}
		strategy, ok := strategyMap[f.DetectorName]
		if !ok {
			continue
		}
		masked := applyStrategy(f.RawValue, strategy)
		result = result[:f.Start] + masked + result[f.End:]
		prevStart = f.Start
	}
	return result
}

// MaskAll applies strategy to every finding using the range and overlap rules of [Mask].
//
// revive:disable-next-line:exported
func MaskAll(text string, findings []sensitive.Finding, strategy Strategy) string {
	if len(findings) == 0 {
		return text
	}

	strategyMap := make(map[sensitive.DetectorName]Strategy)
	for _, f := range findings {
		strategyMap[f.DetectorName] = strategy
	}
	return Mask(text, findings, strategyMap)
}

// applyStrategy applies the given masking strategy to a raw value string.
// All character-level operations use []rune so that multi-byte characters
// (e.g., full-width digits) are handled correctly without breaking UTF-8.
func applyStrategy(raw string, strategy Strategy) string {
	switch strategy {
	case Redact:
		return strings.Repeat("*", runeLen(raw))
	case Last4:
		runes := []rune(raw)
		if len(runes) <= 4 {
			return raw
		}
		return strings.Repeat("*", len(runes)-4) + string(runes[len(runes)-4:])
	case First1Last4:
		runes := []rune(raw)
		if len(runes) <= 5 {
			return raw
		}
		return string(runes[:1]) + strings.Repeat("*", len(runes)-5) + string(runes[len(runes)-4:])
	case Partial:
		return applyPartial(raw)
	case Hash:
		h := sha256.Sum256([]byte(raw))
		return hex.EncodeToString(h[:4])
	default:
		return raw
	}
}

// runeLen returns the number of runes (characters) in s.
func runeLen(s string) int {
	return len([]rune(s))
}

// applyPartial applies context-aware partial masking.
// For email addresses (containing '@'), it preserves the first character of
// the local part and the entire domain. For other values, it behaves like Last4.
// All character-level operations use []rune for multi-byte safety.
func applyPartial(raw string) string {
	atIdx := strings.IndexByte(raw, '@')
	if atIdx > 0 {
		// Email: show first char of local part + domain.
		local := raw[:atIdx]
		domain := raw[atIdx:]
		localRunes := []rune(local)
		if len(localRunes) <= 1 {
			return raw
		}
		return string(localRunes[:1]) + strings.Repeat("*", len(localRunes)-1) + domain
	}
	// Non-email: fall back to Last4 behavior.
	runes := []rune(raw)
	if len(runes) <= 4 {
		return raw
	}
	return strings.Repeat("*", len(runes)-4) + string(runes[len(runes)-4:])
}
