package embargo

import (
	"slices"
	"strings"
)

const redactionMarker = "[REDACTED]"

// Mask replaces overlapping spans with [REDACTED]. Adjacent spans remain separate.
// Invalid ranges redact the entire text. Neither input nor findings is changed.
func Mask(text string, findings []Finding) string {
	return MaskFunc(text, findings, func(Kind, string) string { return redactionMarker })
}

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
	ordered := slices.Clone(findings)
	slices.SortStableFunc(ordered, compareFindings)
	var out strings.Builder
	position := 0
	for i := 0; i < len(ordered); {
		best := ordered[i]
		start, end := best.Start, best.End
		i++
		for i < len(ordered) && ordered[i].Start < end {
			f := ordered[i]
			end = max(end, f.End)
			if preferredKind(f, best) {
				best = f
			}
			i++
		}
		//nolint:errcheck // strings.Builder writes always succeed.
		out.WriteString(text[position:start])
		//nolint:errcheck // strings.Builder writes always succeed.
		out.WriteString(replace(best.Kind, text[start:end]))
		position = end
	}
	//nolint:errcheck // strings.Builder writes always succeed.
	out.WriteString(text[position:])
	return out.String()
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
