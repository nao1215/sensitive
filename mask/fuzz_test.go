package mask_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nao1215/sensitive"
	"github.com/nao1215/sensitive/mask"
)

// maskFuzzSeeds returns inputs that reach a range of detectors, including
// multi-byte values (full-width digits) whose masked form changes byte length.
func maskFuzzSeeds() []string {
	return []string{
		"",
		"user tanaka@example.com paid with 4532015112830366",
		"card ４５３２０１５１１２８３０３６６ and 4532-0151-1283-0366",
		"call 090-1234-5678, mynumber: 123456789018",
		"key: AKIAIOSFODNN7EXAMPLE and sk_live_4eC39HqLyjWDarjtT1zdp7dc",
		"CVV: 123 exp 12/28 sort code: 12-34-56 TID 12345678",
		"from 192.168.0.1 and 2001:db8::1 iban GB82WEST12345698765432",
		"a@example.com,b@example.com;c@example.com",
		"\xff4532015112830366\xfe",
		"CVC 000eXp 01-00",
	}
}

// FuzzMaskAllRedact checks MaskAll with the Redact strategy on the findings
// the Scanner reports:
//   - the result equals the input with each finding replaced by one '*' per
//     rune of its RawValue, and everything between findings untouched;
//   - no finding's RawValue survives at its position, and valid UTF-8 input
//     stays valid UTF-8;
//   - scanning the masked text finds nothing that overlaps a masked span, so
//     the '*' runs never form, or join into, a new detection.
//
// Masking as a whole is not idempotent, and the test does not claim it is:
// context detectors require keywords at word boundaries, so in
// "CVC 000eXp 01-00" the "eXp" glued to "000" is not a keyword, but once
// "000" becomes "***" it is, and "01-00" is found as a card expiry on the
// second pass. That is a first-pass miss outside any masked span, not a leak
// of a masked value.
func FuzzMaskAllRedact(f *testing.F) {
	for _, s := range maskFuzzSeeds() {
		f.Add(s)
	}
	scanner := sensitive.NewScanner(sensitive.WithAll(), sensitive.WithSortByPosition())

	f.Fuzz(func(t *testing.T, text string) {
		findings := scanner.ScanString(text)
		got := mask.MaskAll(text, findings, mask.Redact)

		var want strings.Builder
		prev := 0
		for _, fd := range findings {
			want.WriteString(text[prev:fd.Start])
			want.WriteString(strings.Repeat("*", utf8.RuneCountInString(fd.RawValue)))
			prev = fd.End
		}
		want.WriteString(text[prev:])
		if got != want.String() {
			t.Fatalf("MaskAll(%q) = %q, want %q", text, got, want.String())
		}
		if utf8.ValidString(text) && !utf8.ValidString(got) {
			t.Fatalf("MaskAll turned valid UTF-8 %q into invalid %q", text, got)
		}

		// Locate each masked span in the output. Redact writes one byte per
		// rune, so spans shift left when a value holds multi-byte runes.
		type span struct{ start, end int }
		masked := make([]span, 0, len(findings))
		shift := 0
		for _, fd := range findings {
			n := utf8.RuneCountInString(fd.RawValue)
			masked = append(masked, span{fd.Start - shift, fd.Start - shift + n})
			shift += (fd.End - fd.Start) - n
		}
		for _, again := range scanner.ScanString(got) {
			for _, m := range masked {
				if again.Start < m.end && m.start < again.End {
					t.Fatalf("masked text %q (from %q) is detected again: %s %q at [%d:%d] overlaps masked span [%d:%d]",
						got, text, again.DetectorName, again.RawValue, again.Start, again.End, m.start, m.end)
				}
			}
		}
	})
}

// FuzzMask checks Mask against arbitrary, possibly invalid, findings:
//   - it never panics, whatever the positions or strategy;
//   - a finding whose range is out of bounds, empty, or has no strategy
//     leaves the text unchanged;
//   - a single in-range finding changes only the bytes it covers, and the
//     Redact, Last4, First1Last4 and Partial replacements keep the rune count.
func FuzzMask(f *testing.F) {
	f.Add("card 4532015112830366 end", 5, 21, 0)
	f.Add("mail tanaka@example.com", 5, 23, 3)
	f.Add("full ４５３２０１５１", 5, 29, 2)
	f.Add("short 1234", 6, 10, 1)
	f.Add("hash me", 0, 7, 4)
	f.Add("abc", -1, 2, 0)
	f.Add("abc", 2, 1, 0)
	f.Add("abc", 0, 99, 0)
	f.Add("abc", 0, 3, 99)

	f.Fuzz(func(t *testing.T, text string, start, end, strategy int) {
		const name = sensitive.DetectorName("fuzz")
		st := mask.Strategy(strategy)
		inRange := start >= 0 && end <= len(text) && start < end
		raw := ""
		if inRange {
			raw = text[start:end]
		}
		finding := sensitive.Finding{DetectorName: name, Start: start, End: end, RawValue: raw}

		got := mask.Mask(text, []sensitive.Finding{finding}, map[sensitive.DetectorName]mask.Strategy{name: st})
		if !inRange {
			if got != text {
				t.Fatalf("out-of-range finding [%d:%d] changed %q to %q", start, end, text, got)
			}
			return
		}
		if !strings.HasPrefix(got, text[:start]) || !strings.HasSuffix(got, text[end:]) {
			t.Fatalf("Mask changed bytes outside [%d:%d]: %q -> %q", start, end, text, got)
		}
		replaced := got[start : len(got)-(len(text)-end)]
		switch st {
		case mask.Redact, mask.Last4, mask.First1Last4, mask.Partial:
			if utf8.RuneCountInString(replaced) != utf8.RuneCountInString(raw) {
				t.Fatalf("strategy %d replaced %q (%d runes) with %q (%d runes)",
					st, raw, utf8.RuneCountInString(raw), replaced, utf8.RuneCountInString(replaced))
			}
		case mask.Hash:
			if len(replaced) != 8 {
				t.Fatalf("Hash replaced %q with %q, want 8 hex characters", raw, replaced)
			}
		default:
			if replaced != raw {
				t.Fatalf("unknown strategy %d replaced %q with %q", st, raw, replaced)
			}
		}
		if st == mask.Redact && strings.Trim(replaced, "*") != "" {
			t.Fatalf("Redact left non-'*' characters: %q", replaced)
		}
	})
}
