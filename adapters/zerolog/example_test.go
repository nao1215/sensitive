package embargozerolog_test

import (
	"os"

	"github.com/rs/zerolog"

	"github.com/nao1215/embargo"
	embargozerolog "github.com/nao1215/embargo/adapters/zerolog"
)

func ExampleNewWriter() {
	sink := embargozerolog.NewWriter(os.Stdout, embargo.NewScanner(embargo.WithKinds(embargo.KindEmail)))
	logger := zerolog.New(sink)

	logger.Info().Str("email", "alice@example.com").Msg("checkout")
	if err := sink.Close(); err != nil {
		panic(err)
	}

	// Output: {"level":"info","email":"[REDACTED]","message":"checkout"}
}
