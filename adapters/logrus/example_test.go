package embargologrus_test

import (
	"os"

	"github.com/sirupsen/logrus"

	"github.com/nao1215/embargo"
	embargologrus "github.com/nao1215/embargo/adapters/logrus"
)

func ExampleNewFormatter() {
	logger := logrus.New()
	logger.SetOutput(os.Stdout)
	logger.SetFormatter(embargologrus.NewFormatter(&logrus.JSONFormatter{DisableTimestamp: true}, embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))))

	logger.WithField("email", "alice@example.com").Info("checkout")

	// Output: {"email":"[REDACTED]","level":"info","msg":"checkout"}
}
