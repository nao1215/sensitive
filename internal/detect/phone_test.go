package detect

import (
	"strings"
	"testing"
)

func TestPhoneDetector_Scan(t *testing.T) {
	t.Parallel()
	d := NewPhone()
	tests := []struct {
		name, input, want string
		confidence        float64
	}{
		{name: "UK with spaces", input: "call +44 20 7946 0958", want: "+44 20 7946 0958", confidence: 0.9},
		{name: "UK trunk prefix in parentheses", input: "office +44 (0)20 7946 0958", want: "+44 (0)20 7946 0958", confidence: 0.8},
		{name: "North American area code in parentheses", input: "tel +1 (202) 555-0123", want: "+1 (202) 555-0123", confidence: 0.9},
		{name: "Germany with hyphens", input: "+49-30-901820", want: "+49-30-901820", confidence: 0.8},
		{name: "France with dots", input: "+33.1.23.45.67.89", want: "+33.1.23.45.67.89", confidence: 0.8},
		{name: "Japan", input: "mobile: +81 90-1234-5678", want: "+81 90-1234-5678", confidence: 0.9},
		{name: "India unseparated", input: "+919876543210 confirmed", want: "+919876543210", confidence: 0.8},
		{name: "Niue, seven digits", input: "+683 4002", want: "+683 4002", confidence: 0.8},
		{name: "JSON value", input: `{"phone":"+61 2 9374 4000"}`, want: "+61 2 9374 4000", confidence: 0.9},
		{name: "after tel URI scheme", input: "tel:+442079460958", want: "+442079460958", confidence: 0.9},
		{name: "record label lowers the score", input: "order_id +44 20 7946 0958", want: "+44 20 7946 0958", confidence: 0.4},
		{name: "no plus sign", input: "44 20 7946 0958"},
		{name: "spare country code 28", input: "+28 20 7946 0958"},
		{name: "spare country code 0", input: "+0 20 7946 0958"},
		{name: "signed amount", input: "balance +1000000"},
		{name: "short unseparated number", input: "+4420794609"[:9]},
		{name: "longer than 15 digits", input: "+44 20 7946 0958 1234"},
		{name: "repeated digit placeholder", input: "+1 000 000 0000"},
		{name: "time zone offset", input: "2026-11-19T10:00:00+09:00"},
		{name: "inside an identifier", input: "a+44 20 7946 0958"},
		{name: "after a digit", input: "5+44 20 7946 0958"},
		{name: "double plus", input: "++44 20 7946 0958"},
		{name: "runs into letters", input: "+44 20 7946 0958x"},
		{name: "dotted version", input: "v+1.2.3.4"},
		{name: "short dotted number", input: "+1.2.3.4"},
		{name: "unclosed parenthesis", input: "+1 (202 555-0123"},
		{name: "too few subscriber digits", input: "+44 207"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := d.Scan([]byte(tt.input))
			if tt.want == "" {
				if len(got) != 0 {
					t.Fatalf("Scan(%q) = %+v, want none", tt.input, got)
				}
				return
			}
			if len(got) != 1 || tt.input[got[0].Start:got[0].End] != tt.want || got[0].Confidence != tt.confidence || got[0].DetectorName != NamePhone {
				t.Fatalf("Scan(%q) = %+v, want %q at %.1f", tt.input, got, tt.want, tt.confidence)
			}
		})
	}
}

func TestPhoneRightAfterAnotherNumber(t *testing.T) {
	t.Parallel()
	// The scanner removes a no-break space between two numbers, so the second
	// + follows a digit; it must still match on the first pass.
	input := "+44 20 7946 0958+44 20 7946 0959"
	got := NewPhone().Scan([]byte(input))
	if len(got) != 2 || got[0].End != 16 || got[1].Start != 16 || got[1].End != len(input) {
		t.Fatalf("Scan(%q) = %+v, want two adjacent numbers", input, got)
	}
}

func TestPhoneSeparatorsKeepTheSpanProperty(t *testing.T) {
	t.Parallel()
	d := NewPhone()
	groups := []string{"44", "20", "7946", "0958"}
	for _, separator := range []string{" ", "-", "."} {
		for _, before := range []string{"", " ", "phone=", "(", `"`, "\n"} {
			for _, after := range []string{"", " ", ",", ")", `"`, ".", "\n"} {
				number := "+" + strings.Join(groups, separator)
				input := before + number + after
				got := d.Scan([]byte(input))
				if len(got) != 1 || got[0].Start != len(before) || got[0].End != len(before)+len(number) {
					t.Fatalf("Scan(%q) = %+v, want the span of %q", input, got, number)
				}
			}
		}
	}
}

func TestPhoneCountryCodesArePrefixFree(t *testing.T) {
	t.Parallel()
	codes := strings.Fields(callingCodes)
	seen := map[string]bool{}
	for _, code := range codes {
		if seen[code] {
			t.Fatalf("calling code %s listed twice", code)
		}
		seen[code] = true
	}
	for _, code := range codes {
		for n := 1; n < len(code); n++ {
			if seen[code[:n]] {
				t.Fatalf("calling code %s starts with assigned code %s", code, code[:n])
			}
		}
	}
	if len(codes) < 200 {
		t.Fatalf("only %d calling codes", len(codes))
	}
}
