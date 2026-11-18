package embargo

import (
	"slices"
	"strings"
)

const redactionMarker = "[REDACTED]"

// Mask replaces overlapping spans with [REDACTED]. Adjacent spans remain separate.
// Invalid ranges redact the entire text. Neither input nor findings is changed.
// Masking text twice may mask more, so mask each original value once; the marker
// is not a trusted-input bypass.
func Mask(text string, findings []Finding) string {
	return MaskFunc(text, findings, redact)
}

func redact(Kind, string) string { return redactionMarker }

// MaskFunc replaces each merged span with replace(kind, value), in input order.
// The kind comes from the highest-confidence finding; ties prefer kind, start, then
// descending end. The value covers the full merged span. Adjacent spans stay separate.
// Invalid ranges redact all text without calling replace. A nil callback panics.
func MaskFunc(text string, findings []Finding, replace func(kind Kind, value string) string) string {
	if replace == nil {
		panic("embargo: nil replacement")
	}
	if len(findings) == 0 {
		return text
	}
	for _, f := range findings {
		if f.Start < 0 || f.End <= f.Start || f.End > len(text) {
			return redactionMarker
		}
	}
	return maskOwned(text, slices.Clone(findings), replace)
}

// maskOwned is MaskFunc for a validated findings slice that the caller owns:
// it is sorted in place instead of copied.
func maskOwned(text string, ordered []Finding, replace func(kind Kind, value string) string) string {
	if len(ordered) == 0 {
		return text
	}
	slices.SortStableFunc(ordered, compareFindings)
	best, start, end, next := mergeSpan(ordered, 0)
	if start == 0 && end == len(text) {
		// One merged span covers the text, so no surrounding bytes are copied.
		return replace(best.Kind, text)
	}
	var out strings.Builder
	out.Grow(len(text) + len(redactionMarker))
	position := 0
	for {
		//nolint:errcheck // strings.Builder writes always succeed.
		out.WriteString(text[position:start])
		//nolint:errcheck // strings.Builder writes always succeed.
		out.WriteString(replace(best.Kind, text[start:end]))
		position = end
		if next == len(ordered) {
			break
		}
		best, start, end, next = mergeSpan(ordered, next)
	}
	//nolint:errcheck // strings.Builder writes always succeed.
	out.WriteString(text[position:])
	return out.String()
}

// mergeSpan merges sorted findings from i while they overlap the growing span
// and returns the preferred finding, the span and the index after it.
func mergeSpan(ordered []Finding, i int) (best Finding, start, end, next int) {
	best = ordered[i]
	start, end = best.Start, best.End
	for i++; i < len(ordered) && ordered[i].Start < end; i++ {
		f := ordered[i]
		end = max(end, f.End)
		if preferredKind(f, best) {
			best = f
		}
	}
	return best, start, end, i
}

func preferredKind(a, b Finding) bool {
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return compareFindings(a, b) < 0
}
