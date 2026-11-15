package embargo_test

import (
	"log/slog"
	"os"

	"github.com/nao1215/embargo"
)

func ExampleNewSlogHandler() {
	next := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return attr
		},
	})
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN))
	logger := slog.New(embargo.NewSlogHandler(next, scanner))
	logger.Info("checkout", "email", "alice@example.com", "card", "4532015112830366")

	// Output: level=INFO msg=checkout email=[REDACTED] card=[REDACTED]
}

func ExampleNewSlogHandler_short() {
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
	logger := slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}), scanner))

	logger.Info("checkout", "email", "alice@example.com")

	// Output: {"level":"INFO","msg":"checkout","email":"[REDACTED]"}
}
