package embargo_test

import (
	"testing"

	"github.com/nao1215/embargo"
)

func TestEntropyIgnoresLogLocations(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindHighEntropy))
	for _, location := range []string{
		"/tmp/BuildCache-20261116/Projects/PaymentGateway/RequestDiagnostics/SentryIntegration_test.go",
		"/tmp/claude-1000/-home-nao-ghq-github-com-nao1215-scratchpad/emb-ogp/tests/sentry_integration_test.go",
		"/home/runner/work/embargo/embargo/tests/TestCompatibilityTable_Sentry_safe.go",
		`C:\Users\builder\source\PaymentGatewayIntegration2026\sentry_integration_test.go`,
		"com.example.PaymentGatewayIntegration2026.ProcessAuthorizationRequest",
		"https://logs.example.net/artifacts/PaymentGatewayIntegration2026/RequestDiagnosticOutput.log",
		"PaymentGatewayIntegration2026_RequestDiagnosticOutput.log",
		"cache/q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg/output.log",
		"com.example.q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg.Handler",
		"https://logs.example.net/q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg/output",
		"q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg.log",
	} {
		t.Run(location, func(t *testing.T) {
			t.Parallel()
			if got := scanner.ScanString(location); len(got) != 0 {
				t.Fatalf("location became a secret candidate: %v", got)
			}
		})
	}
}
