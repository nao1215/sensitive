package detect

import "testing"

func TestHighEntropySkipsKubernetesGeneratedNames(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		text string
		want int
	}{
		{`"name":"my-vault-agent-injector-9d457c8b-5pqfx"`, 0},
		{`"pod-name":["my-vault-agent-injector-9d457c8b-5pqfx"]`, 0},
		// A letter such as y or the digit 1 cannot come from the Kubernetes generator.
		{`"name":"my-vault-agent-injector-9d457c8b-5pqfy"`, 1},
		{`"name":"my-vault-agent-injector-9d457c8b-1pqfx"`, 1},
		// Uppercase letters do not occur in DNS-label resource names.
		{`"name":"my-Vault-agent-injector-9d457c8b-5pqfx"`, 1},
	} {
		if got := (&HighEntropy{}).Scan([]byte(tc.text)); len(got) != tc.want {
			t.Errorf("%q: got %v, want %d findings", tc.text, got, tc.want)
		}
	}
}
