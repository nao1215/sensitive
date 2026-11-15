package embargo_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/nao1215/embargo"
)

func TestEntropyRequiresSelection(t *testing.T) {
	t.Parallel()
	const randomID = "q8V2m0NxK7bJ3wTaZ9cF6rHsL5dY1pUg"
	var zero embargo.Scanner
	for _, scanner := range []*embargo.Scanner{&zero, embargo.NewScanner()} {
		if len(scanner.ScanString(randomID)) != 0 {
			t.Fatal("default selected uncertain random tokens")
		}
	}
	for _, scanner := range []*embargo.Scanner{embargo.NewScanner(embargo.WithAll()), embargo.NewScanner(embargo.WithKinds(embargo.KindHighEntropy)), embargo.NewScanner(embargo.WithKinds(), embargo.WithAll())} {
		if got := scanner.ScanString(randomID); len(got) != 1 || got[0].Kind != embargo.KindHighEntropy {
			t.Fatal("explicit entropy selection was lost", got)
		}
	}
	var out bytes.Buffer
	logger := slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(&out, nil), embargo.NewScanner()))
	logger.Info(randomID, "password", "opaque-password")
	if !bytes.Contains(out.Bytes(), []byte(randomID)) || bytes.Contains(out.Bytes(), []byte("opaque-password")) {
		t.Fatal("default key/entropy policy was lost")
	}
}
