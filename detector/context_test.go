package detector

import "testing"

func TestFindKeywordPositions(t *testing.T) {
	t.Parallel()

	data := []byte("token A token B")
	kw := [][]byte{[]byte("token")}
	matches := findKeywordPositions(data, kw)
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2", len(matches))
	}
	if matches[0].start != 0 || matches[0].end != 5 {
		t.Errorf("first match = [%d,%d), want [0,5)", matches[0].start, matches[0].end)
	}
	if matches[1].start != 8 || matches[1].end != 13 {
		t.Errorf("second match = [%d,%d), want [8,13)", matches[1].start, matches[1].end)
	}
}

func TestExtractDigitsNear(t *testing.T) {
	t.Parallel()

	data := []byte("abc 12345 def 67890 xyz")
	pos := 10
	results := extractDigitsNear(data, pos, 10, 5, 5)
	if len(results) != 2 {
		t.Fatalf("got %d sequences, want 2", len(results))
	}
	if string(data[results[0].start:results[0].end]) != "12345" {
		t.Errorf("first seq = %q, want %q", data[results[0].start:results[0].end], "12345")
	}
	if string(data[results[1].start:results[1].end]) != "67890" {
		t.Errorf("second seq = %q, want %q", data[results[1].start:results[1].end], "67890")
	}
}

func TestFindKeywordPositions_WordBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    string
		kw      string
		wantLen int
	}{
		{
			name:    "keyword match is case-insensitive for ASCII letters",
			data:    "Trace Number: 123456",
			kw:      "trace number",
			wantLen: 1,
		},
		{
			name:    "keyword match is case-insensitive with punctuation",
			data:    "EXPIRY: 12/25",
			kw:      "expiry",
			wantLen: 1,
		},
		{
			name:    "keyword at word boundary matches",
			data:    "exp: 12/25",
			kw:      "exp",
			wantLen: 1,
		},
		{
			name:    "keyword embedded in word does not match",
			data:    "this example has no expiry",
			kw:      "exp",
			wantLen: 0,
		},
		{
			name:    "ACH should not match inside REACHED",
			data:    "REACHED destination",
			kw:      "ACH",
			wantLen: 0,
		},
		{
			name:    "ACH at word boundary matches",
			data:    "ACH transaction sent",
			kw:      "ACH",
			wantLen: 1,
		},
		{
			name:    "trace should not match inside backtrace",
			data:    "backtrace dump",
			kw:      "trace",
			wantLen: 0,
		},
		{
			name:    "keyword with trailing punctuation ignores end boundary",
			data:    "MID:123456",
			kw:      "MID:",
			wantLen: 1,
		},
		{
			name:    "keyword followed by digit when keyword ends with letter",
			data:    "exp12",
			kw:      "exp",
			wantLen: 0,
		},
		{
			name:    "keyword at start of data",
			data:    "exp 12/25",
			kw:      "exp",
			wantLen: 1,
		},
		{
			name:    "keyword at end of data",
			data:    "card exp",
			kw:      "exp",
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			matches := findKeywordPositions([]byte(tt.data), [][]byte{[]byte(tt.kw)})
			if len(matches) != tt.wantLen {
				t.Errorf("got %d matches, want %d", len(matches), tt.wantLen)
			}
		})
	}
}

func TestExtractDigitsNear_BoundaryTruncation(t *testing.T) {
	t.Parallel()

	// A long digit sequence "12345678901234567890" spans positions [4..24).
	// With a search radius that cuts the sequence, the truncated portion
	// should NOT be returned even if it falls within the min/max range.
	data := []byte("abc 12345678901234567890 xyz")
	// Search from position 24 with radius 10 → searchStart=14, searchEnd=34.
	// Digits at [4..24): the portion within [14..24) = "7890123456" (10 digits).
	// But position 14 is mid-sequence (data[13]='5' is a digit), so it's truncated.
	results := extractDigitsNear(data, 24, 10, 4, 17)
	if len(results) != 0 {
		for _, r := range results {
			t.Errorf("unexpected truncated sequence: %q", data[r.start:r.end])
		}
	}
}

func TestExtractDigitsNear_CompleteBoundarySequence(t *testing.T) {
	t.Parallel()

	// A digit sequence that starts exactly at the search boundary but
	// is NOT a truncation (the byte before searchStart is not a digit).
	data := []byte("abc 12345 def")
	// Search from position 9 with radius 6 → searchStart=3, searchEnd=15.
	// data[3]=' ', data[4..9)="12345" — starts at 4, not at boundary (3).
	results := extractDigitsNear(data, 9, 6, 5, 5)
	if len(results) != 1 {
		t.Fatalf("got %d sequences, want 1", len(results))
	}
	if string(data[results[0].start:results[0].end]) != "12345" {
		t.Errorf("sequence = %q, want %q", data[results[0].start:results[0].end], "12345")
	}
}

func TestExtractAlphaNumNear(t *testing.T) {
	t.Parallel()

	data := []byte("merchant ABCDE12345FGHI6 and X1")
	pos := 9
	results := extractAlphaNumNear(data, pos, 30, 15, 15)
	if len(results) != 1 {
		t.Fatalf("got %d sequences, want 1", len(results))
	}
	if got := string(data[results[0].start:results[0].end]); got != "ABCDE12345FGHI6" {
		t.Errorf("sequence = %q, want %q", got, "ABCDE12345FGHI6")
	}
}

func TestExtractAlphaNumNear_BoundaryTruncation(t *testing.T) {
	t.Parallel()

	// A 30-char alphanumeric token "ABCDEFGHIJ1234567890KLMNOPQRST" spans [4..34).
	// With a search radius that cuts the token, the truncated portion
	// should NOT be returned even if it falls within the min/max range.
	data := []byte("abc ABCDEFGHIJ1234567890KLMNOPQRST xyz")
	// Search from position 34 with radius 16 → searchStart=18, searchEnd=50.
	// The token at [4..34) is cut at position 18, producing a 16-char fragment.
	// Since data[17] is alphanumeric (part of the token), this is truncated.
	results := extractAlphaNumNear(data, 34, 16, 15, 15)
	if len(results) != 0 {
		for _, r := range results {
			t.Errorf("unexpected truncated sequence: %q", data[r.start:r.end])
		}
	}
}

func TestExtractAlphaNumNear_CompleteBoundarySequence(t *testing.T) {
	t.Parallel()

	// An alphanumeric sequence that starts at a non-truncated position
	// should still be returned.
	data := []byte("abc ABCDE12345FGHI6 def")
	// Search from position 19 with radius 16 → searchStart=3, searchEnd=35.
	// data[3]=' ', data[4..19)="ABCDE12345FGHI6" — starts at 4, not truncated.
	results := extractAlphaNumNear(data, 19, 16, 15, 15)
	if len(results) != 1 {
		t.Fatalf("got %d sequences, want 1", len(results))
	}
	if got := string(data[results[0].start:results[0].end]); got != "ABCDE12345FGHI6" {
		t.Errorf("sequence = %q, want %q", got, "ABCDE12345FGHI6")
	}
}
