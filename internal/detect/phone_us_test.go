package detect

import "testing"

const usPhoneFixture = "202-555-0123"

func TestUSPhoneDetector_Scan(t *testing.T) {
	t.Parallel()
	d := NewUSPhone()
	tests := []struct {
		name, input, wantRaw string
		wantLen              int
		wantMinCon           float64
	}{
		{name: "hyphenated", input: "contact 202-555-0123", wantRaw: usPhoneFixture, wantLen: 1, wantMinCon: 0.9},
		{name: "dotted", input: "call 415.555.0199 now", wantRaw: "415.555.0199", wantLen: 1, wantMinCon: 0.9},
		{name: "spaced", input: "number 312 555 0142", wantRaw: "312 555 0142", wantLen: 1, wantMinCon: 0.7},
		{name: "parenthesized area code", input: "tel: (212) 555-0100", wantRaw: "(212) 555-0100", wantLen: 1, wantMinCon: 0.9},
		{name: "parenthesized without space", input: "(212)555-0100", wantRaw: "(212)555-0100", wantLen: 1, wantMinCon: 0.7},
		{name: "country code is masked with the number", input: "phone +1 202-555-0123", wantRaw: "+1 202-555-0123", wantLen: 1, wantMinCon: 0.9},
		{name: "bare country code", input: "1-800-555-0199", wantRaw: "1-800-555-0199", wantLen: 1, wantMinCon: 0.7},
		{name: "two numbers", input: "202-555-0123 or 303-555-0145", wantRaw: usPhoneFixture, wantLen: 2, wantMinCon: 0.7},
		{name: "business label lowers the score", input: "order 202-555-0123", wantRaw: usPhoneFixture, wantLen: 1, wantMinCon: 0.4},
		{name: "bare digit run", input: "id 2025550123", wantLen: 0},
		{name: "mixed separators", input: "202-555.0123", wantLen: 0},
		{name: "area code starting with 1", input: "102-555-0123", wantLen: 0},
		{name: "area code middle digit 9", input: "292-555-0123", wantLen: 0},
		{name: "exchange starting with 1", input: "202-155-0123", wantLen: 0},
		{name: "N11 exchange", input: "202-911-0123", wantLen: 0},
		{name: "longer number", input: "202-555-0123-45", wantLen: 0},
		{name: "inside an identifier", input: "x202-555-0123", wantLen: 0},
		{name: "dotted version", input: "v1.202.555.0123", wantLen: 0},
		{name: "path segment", input: "/202-555-0123", wantLen: 0},
		{name: "date and time", input: "2026-11-17 10:00:00", wantLen: 0},
		{name: "IPv4 address", input: "203.0.113.7", wantLen: 0},
		{name: "too short", input: "202-555-012", wantLen: 0},
		{name: "no four-digit line", input: "202-555-012 345-678", wantLen: 0},
		{name: "unclosed parenthesis", input: "(212 555-0100", wantLen: 0},
		{name: "parenthesized with dot", input: "(212) 555.0100", wantLen: 0},
		{name: "sentence end", input: "Call 202-555-0123.", wantRaw: usPhoneFixture, wantLen: 1, wantMinCon: 0.9},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertScanCase(t, d, tt.input, tt.wantLen, tt.wantRaw, tt.wantMinCon)
		})
	}
}

func TestUSPhoneScoresAndName(t *testing.T) {
	t.Parallel()
	d := NewUSPhone()
	if d.Name() != NameUSPhone || len(d.Hints()) == 0 {
		t.Fatal("name or hints missing")
	}
	for input, want := range map[string]float64{usPhoneFixture: 0.7, "mobile 202-555-0123": 0.9, "invoice 202-555-0123": 0.4, "fax: +1 (212) 555-0100": 0.9} {
		findings := d.Scan([]byte(input))
		if len(findings) != 1 || findings[0].Confidence != want {
			t.Errorf("%q: %+v, want confidence %v", input, findings, want)
		}
	}
	if got := d.Scan([]byte("x+1 202-555-0123")); len(got) != 1 || got[0].Start != len("x+1 ") {
		t.Errorf("country code after an identifier must stay outside: %+v", got)
	}
	if got := d.Scan([]byte("tel 1-202-555-0123")); len(got) != 1 || got[0].Start != len("tel ") {
		t.Errorf("country code start: %+v", got)
	}
}
