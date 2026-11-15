package embargo

import "testing"

//nolint:goconst // State names match the experiment benchmark axes.
func BenchmarkNarrowing(b *testing.B) {
	clean, dirty := experimentTexts(b)
	policies := []struct {
		option ScannerOption
		name   string
	}{
		{name: "all", option: WithAll()},
		{name: "kinds1", option: WithKinds(KindEmail)},
		{name: "kinds3", option: WithKinds(KindEmail, KindPAN, KindCredential)},
		{name: "kinds8", option: WithKinds(KindEmail, KindPAN, KindCredential, KindJPPhone, KindIPAddr, KindGitHubToken, KindServiceToken, KindPrivateKeyPEM)},
	}
	for _, policy := range policies {
		scanner := NewScanner(policy.option)
		for _, state := range []string{"clean", "dirty"} {
			input := clean
			if state == "dirty" {
				input = dirty
			}
			b.Run(policy.name+"/"+state, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(input)))
				for b.Loop() {
					scanner.Scan(input)
				}
			})
		}
	}
}
