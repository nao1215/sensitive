package detect

import (
	"testing"
)

func TestACHTraceDetector_Scan(t *testing.T) {
	t.Parallel()

	d := NewACHTrace()
	tests := []struct {
		name       string
		input      string
		wantRaw    string
		wantLen    int
		wantMinCon float64
	}{
		{
			name:       "valid ACH trace with keyword",
			input:      "ACH trace 021000021123456",
			wantLen:    1,
			wantRaw:    "021000021123456",
			wantMinCon: 0.7,
		},
		{
			name:       "valid with trace keyword",
			input:      "trace number: 021000021123456",
			wantLen:    1,
			wantRaw:    "021000021123456",
			wantMinCon: 0.7,
		},
		{
			name:    "no keyword",
			input:   "payment 021000021123456",
			wantLen: 0,
		},
		{
			name:    "invalid prefix",
			input:   "ACH trace 991000021123456",
			wantLen: 0,
		},
		{
			name:    "wrong length",
			input:   "ACH trace 0210000211234567",
			wantLen: 0,
		},
		{
			//nolint:goconst // Each test states its fixture and expected result independently.
			name:    "empty input",
			input:   "",
			wantLen: 0,
		},
		{
			name:    "bare trace keyword should not match (stack trace context)",
			input:   "trace: 021000021123456",
			wantLen: 0,
		},
		{
			name:    "bare Trace keyword should not match",
			input:   "Trace 021000021123456",
			wantLen: 0,
		},
		{
			name:    "invalid ODFI routing prefix 99 should not match",
			input:   "ACH trace 990000021123456",
			wantLen: 0,
		},
		{
			name:    "invalid ODFI routing prefix 50 should not match",
			input:   "ACH trace 500000021123456",
			wantLen: 0,
		},
		{
			name:    "14 digits should not match (too short)",
			input:   "ACH trace 02100002112345",
			wantLen: 0,
		},
		{
			name:    "16 digits should not match (too long)",
			input:   "ACH trace 0210000211234567",
			wantLen: 0,
		},
		{
			name:       "compound ACH trace keyword should match",
			input:      "ACH trace: 021000021123456",
			wantLen:    1,
			wantRaw:    "021000021123456",
			wantMinCon: 0.7,
		},
		{
			name:       "trace number compound keyword should match",
			input:      "trace number 021000021123456",
			wantLen:    1,
			wantRaw:    "021000021123456",
			wantMinCon: 0.7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d; findings=%+v", len(findings), tt.wantLen, findings)
			}
			if tt.wantLen == 0 {
				return
			}
			if tt.wantRaw != "" && tt.input[findings[0].Start:findings[0].End] != tt.wantRaw {
				t.Errorf("matched text = %q, want %q", tt.input[findings[0].Start:findings[0].End], tt.wantRaw)
			}
			for _, f := range findings {
				if f.Confidence < tt.wantMinCon {
					t.Errorf("Confidence = %f, want >= %f", f.Confidence, tt.wantMinCon)
				}
			}
		})
	}
}

func TestACHTraceDetector_Validation(t *testing.T) {
	t.Parallel()

	d := NewACHTrace()
	findings := d.Scan([]byte("ACH trace 021000021123456"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	matched := "ACH trace 021000021123456"[findings[0].Start:findings[0].End]
	if matched[:8] != "02100002" {
		t.Errorf("ODFIRoutingNumber = %q, want %q", matched[:8], "02100002")
	}
}

func TestACHTraceDetector_Name(t *testing.T) {
	t.Parallel()

	d := NewACHTrace()
	if d.Name() != NameACHTrace {
		t.Errorf("Name() = %q, want %q", d.Name(), NameACHTrace)
	}
}

func TestACHTraceDetector_KeywordVariations(t *testing.T) {
	t.Parallel()

	d := NewACHTrace()
	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{
			name:    "ACH Trace (title case) should match",
			input:   "ACH Trace: 021000021123456",
			wantLen: 1,
		},
		{
			name:    "ACH TRACE (all caps) should match",
			input:   "ACH TRACE 021000021123456",
			wantLen: 1,
		},
		{
			name:    "trace # should match",
			input:   "trace # 021000021123456",
			wantLen: 1,
		},
		{
			name:    "Trace # should match",
			input:   "Trace # 021000021123456",
			wantLen: 1,
		},
		{
			name:    "TRACE # should match",
			input:   "TRACE # 021000021123456",
			wantLen: 1,
		},
		{
			name:    "Trace# (no space) should match",
			input:   "Trace#021000021123456",
			wantLen: 1,
		},
		{
			name:    "Trace number (mixed case) should match",
			input:   "Trace number: 021000021123456",
			wantLen: 1,
		},
		{
			name:    "Trace no (mixed case) should match",
			input:   "Trace no 021000021123456",
			wantLen: 1,
		},
		{
			name:    "Ach trace (mixed case) should match",
			input:   "Ach trace 021000021123456",
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d; findings=%+v", len(findings), tt.wantLen, findings)
			}
		})
	}
}

func TestACHTraceDetector_Hints(t *testing.T) {
	t.Parallel()

	d := NewACHTrace()
	hints := d.Hints()
	if len(hints) == 0 {
		t.Error("Hints() returned empty slice, want at least one hint")
	}
}
