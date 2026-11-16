package detect

import "testing"

func TestCountryConstructorRejectsUnsupportedName(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("unsupported country accepted")
		}
	}()
	NewCountry("unsupported")
}

func TestCountryRejectedBoundaries(t *testing.T) {
	t.Parallel()
	if _, _, ok := countryCandidate([]byte("A"), 0, "X"); ok {
		t.Fatal("non-check digit accepted")
	}
}
