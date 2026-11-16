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
