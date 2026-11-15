package embargo

import "testing"

type measuredJSONDetector struct{ bytes int }

func (d *measuredJSONDetector) Scan(data []byte) []Finding { d.bytes += len(data); return nil }

func TestScanBudgetBoundary(t *testing.T) {
	t.Parallel()
	counter := &measuredJSONDetector{}
	scanner := &eventScanner{scanner: NewScanner(WithKinds(), WithDetector(counter)), remaining: 6}
	if got, err := scanner.maskScalar("abc", "k"); err != nil || got != "abc" {
		t.Fatal("exact budget should preserve a clean value")
	}
	for _, context := range []string{"", "key"} {
		if _, err := scanner.maskScalar("x", context); err == nil {
			t.Fatal("exhausted budget accepted another scan")
		}
	}
	if counter.bytes != 6 {
		t.Fatal("over-budget input reached the detector")
	}
}
