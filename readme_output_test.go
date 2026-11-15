package embargo_test

import (
	"log/slog"
	"testing"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

func TestReadmeCheckOutput(t *testing.T) {
	t.Parallel()
	recorder := embargotest.New(t)
	logger := slog.New(slog.NewJSONHandler(recorder.Writer("logs"), nil))

	logger.Info("accepted", "token", embargo.NewSecret(recorder.Canary()))

	//nolint:goconst // The README test shows the literal expected output.
	recorder.ExpectJSON("logs", nil, map[string]string{"token": "[REDACTED]"}, 1)
	recorder.Check()
}
