package tests

import (
	"strings"
	"testing"

	"github.com/nao1215/embargo"
)

func TestAuditDiagnosticRecipe(t *testing.T) {
	t.Parallel()
	const input = `{"order_id":"4111111111111111","request_id":"DEUTDEFF","card":"4242424242424242","authorization":"Bearer pretend-client-value"}`
	const want = `{"order_id":"4111111111111111","request_id":"DEUTDEFF","card":"[REDACTED]","authorization":"[REDACTED]"}`
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindPAN, embargo.KindCredential), embargo.WithMinConfidence(.7))
	output, err := scanner.MaskJSON([]byte(input))
	if err != nil || string(output) != want {
		t.Fatalf("recipe lost diagnostics or retained secrets: %s, %v", output, err)
	}
	// A business label lowers confidence even when its contents really are a card.
	if len(scanner.ScanString("order_id=4111111111111111")) != 0 {
		t.Fatal("documented mislabeled-card tradeoff changed")
	}
	baseline, err := embargo.NewScanner().MaskJSON([]byte(input))
	if err != nil || !strings.Contains(string(baseline), "DEUTDEFF") || strings.Contains(string(baseline), "4111111111111111") {
		t.Fatalf("default ID policy changed: %s", baseline)
	}
}
