package tests

import (
	"encoding/json"
	"testing"

	"github.com/nao1215/embargo"
)

// A field decoder cannot clear a value when encoding/json never calls it.
func TestInputOuterDecode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		text    string
		wantErr bool
	}{
		{name: "absent field retains earlier value", text: `{}`},
		{name: "invalid outer JSON retains earlier value", text: `{"token":"new"`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var reused, fresh struct {
				Token embargo.Input[string] `json:"token"`
			}
			if err := reused.Token.UnmarshalText([]byte("previous")); err != nil {
				t.Fatal(err)
			}

			if err := json.Unmarshal([]byte(tc.text), &reused); (err != nil) != tc.wantErr {
				t.Fatalf("reused object: unexpected error %v", err)
			}
			if got := reused.Token.Secret().Reveal(); got != "previous" {
				t.Fatalf("field decoder was unexpectedly called: %q", got)
			}

			if err := json.Unmarshal([]byte(tc.text), &fresh); (err != nil) != tc.wantErr {
				t.Fatalf("fresh object: unexpected error %v", err)
			}
			if got := fresh.Token.Secret().Reveal(); got != "" {
				t.Fatalf("fresh object retained a value: %q", got)
			}
		})
	}
}
