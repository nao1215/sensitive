package embargo

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nao1215/embargo/internal/saferecord"
)

func TestScanBudgetBoundary(t *testing.T) {
	t.Parallel()
	counter := &measuredJSONDetector{}
	scanner := &eventScanner{scanner: NewScanner(WithKinds(), WithDetector(counter)), remaining: 6}
	if got, err := scanner.maskScalar(t.Context(), "abc", "k"); err != nil || got != "abc" {
		t.Fatal("exact budget should preserve a clean value")
	}
	for _, context := range []string{"", "key"} {
		if _, err := scanner.maskScalar(t.Context(), "x", context); err == nil {
			t.Fatal("exhausted budget accepted another scan")
		}
	}
	if counter.bytes != 6 {
		t.Fatal("over-budget input reached the detector")
	}
}

func TestSanitizationInternalBoundaries(t *testing.T) {
	t.Parallel()
	handler, ok := NewSlogHandler(slog.DiscardHandler, NewScanner()).(*slogHandler)
	if !ok {
		t.Fatal("unexpected handler")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := handler.sanitizeAttr(ctx, slog.String("key", "private"), 0, ""); !errors.Is(err, saferecord.ErrCanceled) {
		t.Fatal("canceled attribute accepted")
	}
	if _, err := handler.sanitizeBytes(ctx, "key", "key", []byte("private")); !errors.Is(err, saferecord.ErrCanceled) {
		t.Fatal("canceled bytes accepted")
	}
	if _, err := handler.sanitizeScalar(t.Context(), "value", "value", slog.Float64Value(math.Inf(1))); err == nil {
		t.Fatal("non-JSON scalar accepted")
	}
	if _, _, err := handler.sanitizeAttr(t.Context(), slog.String(strings.Repeat("x", maxScanBytes+1), "value"), 0, ""); !errors.Is(err, saferecord.ErrSizeLimit) {
		t.Fatal("oversize key accepted")
	}
	if _, _, err := handler.sanitizeAttr(t.Context(), slog.String("key", "value"), 0, strings.Repeat("x", maxScanBytes)); !errors.Is(err, saferecord.ErrSizeLimit) {
		t.Fatal("oversize group path accepted")
	}
	if got := joinedKey("group", ""); got != "group" {
		t.Fatal("empty group changed path")
	}
	value := maskedJSON(`{"safe":true}`)
	if value.String() != string(value) {
		t.Fatal("frozen value changed in a fmt-based handler")
	}
	scan := eventScanner{scanner: NewScanner(), remaining: maxScanBytes}
	if _, err := scan.maskHTTPHeaders(ctx, http.Header{}); !errors.Is(err, saferecord.ErrCanceled) {
		t.Fatal("canceled headers accepted")
	}
	if _, err := scan.httpTarget(ctx, &url.URL{}); !errors.Is(err, saferecord.ErrCanceled) {
		t.Fatal("canceled target accepted")
	}
	if _, err := scan.httpQuery(t.Context(), strings.Repeat("token=&", 65000)); !errors.Is(err, saferecord.ErrSizeLimit) {
		t.Fatal("query expansion exceeded output budget", err)
	}
}

func TestJoinedKeyFindingMustCrossSeparator(t *testing.T) {
	t.Parallel()
	const path = "ab.cd"
	for _, tc := range []struct {
		name       string
		start, end int
		crosses    bool
	}{
		{name: "ancestor", start: 0, end: 2, crosses: false},
		{name: "ends after separator", start: 0, end: 3, crosses: false},
		{name: "crosses separator", start: 0, end: 4, crosses: true},
		{name: "starts at separator", start: 2, end: 4, crosses: false},
		{name: "descendant", start: 3, end: 5, crosses: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			scanner := NewScanner(WithKinds(), WithDetector(literalDetector{{Kind: "fixture", Start: tc.start, End: tc.end, Confidence: 1}}))
			scan := eventScanner{scanner: scanner, remaining: len(path)}
			got, err := scan.joinedKeySensitive(t.Context(), path, len("ab"))
			if err != nil || got != tc.crosses || scan.remaining != 0 {
				t.Fatalf("crossing = %v, error = %v, remaining = %d", got, err, scan.remaining)
			}
		})
	}
}

func TestCanonicalIntegerMatchesExactIntegerFixedPoints(t *testing.T) {
	t.Parallel()
	tests := []struct {
		text string
		want bool
	}{
		{"0", true},
		{"17", true},
		{"-17", true},
		{"9223372036854775808", true},
		{"-0", false},
		{"007", false},
		{"-01", false},
		{"1e2", false},
		{"1.0", false},
		{"-", false},
		{"", false},
		{"12a", false},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			t.Parallel()
			if got := canonicalInteger(tt.text); got != tt.want {
				t.Fatalf("canonicalInteger(%q) = %v, want %v", tt.text, got, tt.want)
			}
			if !tt.want {
				return
			}
			// A canonical spelling is its own exact integer, so the second scan is redundant.
			if integer, err := exactInteger(tt.text); err != nil || integer != tt.text {
				t.Fatalf("exactInteger(%q) = %q, %v", tt.text, integer, err)
			}
		})
	}
}

func TestMaskBytesMatchesMaskScalar(t *testing.T) {
	t.Parallel()
	scanner := NewScanner(WithKinds(KindEmail, KindPAN))
	for _, value := range []string{"clean application value", documentedEmail, "4111111111111111", "4111111111111111 ", "-17", "true", "null", ""} {
		for _, key := range []string{"", "card", credentialFixtureKey} {
			byText := eventScanner{scanner: scanner, remaining: maxScanBytes}
			want, wantErr := byText.maskScalar(context.Background(), value, key)
			byBytes := eventScanner{scanner: scanner, remaining: maxScanBytes}
			got, changed, err := byBytes.maskBytes(context.Background(), []byte(value), key)
			if !changed {
				got = value
			}
			if got != want || !errors.Is(err, wantErr) || changed != (want != value) || byText.remaining != byBytes.remaining {
				t.Errorf("maskBytes(%q, %q) = %q, %v, %v; maskScalar = %q, %v", value, key, got, changed, err, want, wantErr)
			}
		}
	}
}

func TestEncodedTextBoundaries(t *testing.T) {
	t.Parallel()
	encode := func(text string) string { return base64.StdEncoding.EncodeToString([]byte(text)) }
	email := "a@example.com"
	atMax := email + strings.Repeat(" ", maxEncodedText/4*3-len(email))
	overMax := atMax + "   "
	tests := []struct {
		name, value string
		hidden      bool
	}{
		{"shortest scanned length", encode(email), true},
		{"shorter values are not scanned", encode("a@b.co"), false},
		{"longest scanned length", encode(atMax), true},
		{"one quantum longer is not scanned", encode(overMax), false},
		{"plus and slash belong to the alphabet", encode(email + "  ???>>>"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := NewScanner().MaskJSON([]byte(`{"b":"` + tt.value + `"}`))
			if err != nil {
				t.Fatal(err)
			}
			want := `{"b":"` + tt.value + `"}`
			if tt.hidden {
				want = `{"b":"[REDACTED]"}`
			}
			if string(got) != want {
				t.Fatalf("len %d: got %.80s, want %.80s", len(tt.value), got, want)
			}
		})
	}
}

func TestScalarEncodedText(t *testing.T) {
	t.Parallel()
	// HTTP header and query values take the scalar path rather than the JSON
	// byte path, so it applies the same encoded-text rule.
	encoded := base64.StdEncoding.EncodeToString([]byte("a@example.com"))
	scanner := eventScanner{scanner: NewScanner(), remaining: maxScanBytes}
	for value, want := range map[string]string{
		encoded:              redactionMarker,
		"mail a@example.com": "mail " + redactionMarker,
		"plain-header-value": "plain-header-value",
	} {
		got, err := scanner.scanScalar(t.Context(), value, "X-Note")
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("scanScalar(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestPrintableText(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, data string
		want       bool
	}{
		{"ASCII", "plain", true},
		{"tab, newline and carriage return", "a\tb\nc\rd", true},
		{"encoded replacement character", "\uFFFD", true},
		{"control byte", "a\x01b", false},
		{"invalid UTF-8", "a\xffb", false},
		{"truncated sequence", "a\xc3", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := printableText([]byte(tt.data)); got != tt.want {
				t.Fatalf("printableText(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}
