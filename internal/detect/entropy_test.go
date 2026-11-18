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

func TestKubernetesGeneratedNameNeedsAWord(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"my-9d457c8b-5pqfx", true},
		// A one-letter or mixed segment is not a human-chosen word.
		{"q-9d457c8b-5pqfx", false},
		{"q7-9d457c8b-5pqfx", false},
		{"-5pqfx", false},
	} {
		if got := kubernetesGeneratedName([]byte(tc.name)); got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestHighEntropySkipsPaginationCursors(t *testing.T) {
	t.Parallel()
	const cursor = "eyJ2IjoibWV0YS5rOHMuaW8vdjEiLCJydiI6NjU3NzY2Nywic3RhcnQiOiJrdWJlcm5ldGVzLWRhc2hib2FyZCJ9"
	for _, tc := range []struct {
		text string
		want int
	}{
		{"/apis/events.k8s.io/v1/events?continue=" + cursor + "&limit=500", 0},
		{`{"cursor":"` + cursor + `"}`, 0},
		{"next_cursor=" + cursor, 0},
		// The same value under any other key is still an opaque candidate.
		{"/callback?state=" + cursor + "&limit=500", 1},
		{"session=" + cursor, 1},
	} {
		if got := (&HighEntropy{}).Scan([]byte(tc.text)); len(got) != tc.want {
			t.Errorf("%q: got %v, want %d findings", tc.text, got, tc.want)
		}
	}
}
