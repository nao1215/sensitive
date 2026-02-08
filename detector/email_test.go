package detector_test

import (
	"testing"

	"github.com/nao1215/sensitive/detector"
)

func TestEmailDetector_Scan(t *testing.T) {
	t.Parallel()

	d := detector.NewEmail()
	tests := []struct {
		name       string
		input      string
		wantLen    int
		wantRaw    string
		wantMinCon float64
	}{
		{
			name:       "simple email",
			input:      "contact tanaka@example.com for info",
			wantLen:    1,
			wantRaw:    "tanaka@example.com",
			wantMinCon: 0.7,
		},
		{
			name:       "email with subdomain",
			input:      "mail to user@mail.example.co.jp",
			wantLen:    1,
			wantRaw:    "user@mail.example.co.jp",
			wantMinCon: 0.7,
		},
		{
			name:       "email with plus addressing",
			input:      "send to user+tag@example.com",
			wantLen:    1,
			wantRaw:    "user+tag@example.com",
			wantMinCon: 0.7,
		},
		{
			name:       "multiple emails",
			input:      "from alice@example.com to bob@example.org",
			wantLen:    2,
			wantRaw:    "",
			wantMinCon: 0.7,
		},
		{
			name:       "email in angle brackets",
			input:      "<admin@example.com>",
			wantLen:    1,
			wantRaw:    "admin@example.com",
			wantMinCon: 0.7,
		},

		// False positives that should NOT be detected
		{
			name:    "@ alone",
			input:   "@ sign",
			wantLen: 0,
		},
		{
			name:    "no domain",
			input:   "user@",
			wantLen: 0,
		},
		{
			name:    "no local part",
			input:   "@example.com",
			wantLen: 0,
		},
		{
			name:    "no TLD",
			input:   "user@localhost",
			wantLen: 0,
		},
		{
			name:    "empty input",
			input:   "",
			wantLen: 0,
		},
		{
			name:    "single char TLD",
			input:   "user@example.c",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := d.Scan([]byte(tt.input))
			if len(findings) != tt.wantLen {
				t.Fatalf("got %d findings, want %d: %+v", len(findings), tt.wantLen, findings)
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

func TestEmailDetector_UppercaseTLD(t *testing.T) {
	t.Parallel()

	d := detector.NewEmail()
	findings := d.Scan([]byte("user@EXAMPLE.COM"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	// Known TLD "COM" should be recognized case-insensitively, giving >= 0.9.
	if findings[0].Confidence < 0.9 {
		t.Errorf("Confidence = %f, want >= 0.9 for uppercase known TLD", findings[0].Confidence)
	}
}

func TestEmailDetector_Detail(t *testing.T) {
	t.Parallel()

	d := detector.NewEmail()
	findings := d.Scan([]byte("tanaka@example.com"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	detail, ok := findings[0].EmailDetail()
	if !ok {
		t.Fatal("EmailDetail() returned false")
	}
	if detail.Local != "tanaka" {
		t.Errorf("Local = %q, want %q", detail.Local, "tanaka")
	}
	if detail.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", detail.Domain, "example.com")
	}
}

func TestEmailDetector_Name(t *testing.T) {
	t.Parallel()

	d := detector.NewEmail()
	if d.Name() != detector.NameEmail {
		t.Errorf("Name() = %q, want %q", d.Name(), detector.NameEmail)
	}
}

func TestEmailDetector_Hints(t *testing.T) {
	t.Parallel()

	d := detector.NewEmail()
	hints := d.Hints()
	if len(hints) != 1 || string(hints[0]) != "@" {
		t.Errorf("Hints() = %v, want [[@]]", hints)
	}
}

func TestEmailDetector_ConsecutiveDots(t *testing.T) {
	t.Parallel()

	d := detector.NewEmail()
	findings := d.Scan([]byte("user@example..com"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Confidence > 0.9 {
		t.Errorf("Confidence = %f, want <= 0.9 for consecutive dots", findings[0].Confidence)
	}
}

func TestEmailDetector_DotAtLocalEnd(t *testing.T) {
	t.Parallel()

	d := detector.NewEmail()
	findings := d.Scan([]byte("user.@example.com"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for dot at end of local part, want 0", len(findings))
	}
}

func TestEmailDetector_DotAtLocalStart(t *testing.T) {
	t.Parallel()

	d := detector.NewEmail()
	findings := d.Scan([]byte(".user@example.com"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for dot at start of local part, want 0", len(findings))
	}
}

func TestEmailDetector_UnknownTLD(t *testing.T) {
	t.Parallel()

	d := detector.NewEmail()
	findings := d.Scan([]byte("user@example.xyz"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Confidence >= 0.9 {
		t.Errorf("Confidence = %f, want < 0.9 for unknown TLD", findings[0].Confidence)
	}
}

func TestEmailDetector_TrailingDotDomain(t *testing.T) {
	t.Parallel()

	d := detector.NewEmail()
	findings := d.Scan([]byte("user@example.com."))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RawValue != "user@example.com" {
		t.Errorf("RawValue = %q, want %q", findings[0].RawValue, "user@example.com")
	}
}

func TestEmailDetector_TrailingDashDomain(t *testing.T) {
	t.Parallel()

	d := detector.NewEmail()
	findings := d.Scan([]byte("user@example.com-"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RawValue != "user@example.com" {
		t.Errorf("RawValue = %q, want %q", findings[0].RawValue, "user@example.com")
	}
}

func TestEmailDetector_NumericTLD(t *testing.T) {
	t.Parallel()

	d := detector.NewEmail()
	// TLD with digits should not be detected.
	findings := d.Scan([]byte("user@example.c0m"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for numeric TLD, want 0", len(findings))
	}
}

func TestEmailDetector_ConsecutiveDotsLocal(t *testing.T) {
	t.Parallel()

	d := detector.NewEmail()
	// Consecutive dots in local part are forbidden by RFC 5321.
	findings := d.Scan([]byte("user..name@example.com"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for consecutive dots in local part, want 0", len(findings))
	}
}

func TestEmailDetector_DomainLabelStartsWithDash(t *testing.T) {
	t.Parallel()

	d := detector.NewEmail()
	// Domain label starting with '-' is invalid per RFC 5321.
	findings := d.Scan([]byte("user@-example.com"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for domain label starting with dash, want 0", len(findings))
	}
}

func TestEmailDetector_DomainLabelEndsWithDash(t *testing.T) {
	t.Parallel()

	d := detector.NewEmail()
	// Domain label ending with '-' (before dot) is invalid per RFC 5321.
	findings := d.Scan([]byte("user@example-.com"))
	if len(findings) != 0 {
		t.Errorf("got %d findings for domain label ending with dash, want 0", len(findings))
	}
}
