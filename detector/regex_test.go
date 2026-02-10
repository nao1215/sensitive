package detector_test

import (
	"regexp"
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestNewRegex_nilPatternPanics(t *testing.T) {
	t.Parallel()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("NewRegex(nil pattern) did not panic")
		}
		msg, ok := r.(string)
		if !ok || msg != "detector.NewRegex: pattern must not be nil" {
			t.Errorf("unexpected panic value: %v", r)
		}
	}()
	detector.NewRegex("test", nil, nil, 0.5)
}

func TestRegexDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detector.NewRegex(
		detector.DetectorName("internal_id"),
		regexp.MustCompile(`PROJ-\d{6}`),
		[][]byte{[]byte("PROJ-")},
		0.8,
	)

	tests := []struct {
		name       string
		input      string
		wantLen    int
		wantRaw    string
		wantMinCon float64
	}{
		{
			name:       "matching pattern",
			input:      "ticket PROJ-123456 assigned",
			wantLen:    1,
			wantRaw:    "PROJ-123456",
			wantMinCon: 0.8,
		},
		{
			name:       "multiple matches",
			input:      "PROJ-111111 and PROJ-222222",
			wantLen:    2,
			wantRaw:    "",
			wantMinCon: 0.8,
		},
		{
			name:    "no match",
			input:   "ticket TASK-123456 assigned",
			wantLen: 0,
		},
		{
			name:    "empty input",
			input:   "",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d", len(findings), tt.wantLen)
			}
			if tt.wantLen > 0 && tt.wantRaw != "" {
				if findings[0].RawValue != tt.wantRaw {
					t.Errorf("RawValue = %q, want %q", findings[0].RawValue, tt.wantRaw)
				}
			}
			if tt.wantLen > 0 && tt.wantMinCon > 0 {
				if findings[0].Confidence < tt.wantMinCon {
					t.Errorf("Confidence = %f, want >= %f", findings[0].Confidence, tt.wantMinCon)
				}
			}
		})
	}
}

func TestRegexDetector_Name(t *testing.T) {
	t.Parallel()

	d := detector.NewRegex(detector.DetectorName("test"), regexp.MustCompile(`test`), nil, 0.5)
	if d.Name() != detector.DetectorName("test") {
		t.Errorf("Name() = %q, want %q", d.Name(), detector.DetectorName("test"))
	}
}

func TestRegexDetector_Hints(t *testing.T) {
	t.Parallel()

	hints := [][]byte{[]byte("PROJ-")}
	d := detector.NewRegex(detector.DetectorName("test"), regexp.MustCompile(`PROJ-\d+`), hints, 0.5)
	got := d.Hints()
	if len(got) != 1 || string(got[0]) != "PROJ-" {
		t.Errorf("Hints() = %v, want [[PROJ-]]", got)
	}
}

func TestRegexDetector_NilHints(t *testing.T) {
	t.Parallel()

	d := detector.NewRegex(detector.DetectorName("test"), regexp.MustCompile(`test`), nil, 0.5)
	got := d.Hints()
	if got != nil {
		t.Errorf("Hints() = %v, want nil", got)
	}
}

func TestNewRegex_confidenceIsClamped(t *testing.T) {
	t.Parallel()

	t.Run("negative confidence is clamped to 0", func(t *testing.T) {
		t.Parallel()

		d := detector.NewRegex("test", regexp.MustCompile(`test`), nil, -0.5)
		findings := d.Scan([]byte("test"))
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		if findings[0].Confidence != 0 {
			t.Errorf("Confidence = %f, want 0", findings[0].Confidence)
		}
	})

	t.Run("confidence above 1 is clamped to 1", func(t *testing.T) {
		t.Parallel()

		d := detector.NewRegex("test", regexp.MustCompile(`test`), nil, 1.5)
		findings := d.Scan([]byte("test"))
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		if findings[0].Confidence != 1.0 {
			t.Errorf("Confidence = %f, want 1.0", findings[0].Confidence)
		}
	})
}
