package embargologrus_test

import (
	"encoding/json"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/nao1215/embargo"
	embargologrus "github.com/nao1215/embargo/adapters/logrus"
	"github.com/nao1215/embargo/embargotest"
)

type objectCanary struct{ value string }

//nolint:goconst // The real marshaler deliberately emits literal sensitive fixtures.
func (o objectCanary) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"token": o.value, "email": "alice@example.com"})
}

//nolint:goconst // Keep literal expected bytes beside the real logger calls.
func TestCustomJSONFields(t *testing.T) {
	t.Parallel()
	canary := "public-marshaler-canary"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail), embargo.WithDetector(literal{value: []byte(canary)}))
	r := embargotest.New(t, embargotest.WithCanary([]byte(canary)), embargotest.WithScanner(scanner))
	logger := logrus.New()
	logger.SetOutput(r.Writer("out"))
	logger.SetFormatter(embargologrus.NewFormatter(&logrus.JSONFormatter{DisableTimestamp: true}, scanner))
	logger.WithField("pre", objectCanary{value: canary}).WithField("object", objectCanary{value: canary}).Info("event")
	r.ExpectJSON("out", []string{"object"}, map[string]string{"token": "[REDACTED]", "email": "[REDACTED]"}, 1)
	if !r.Check() {
		t.Fatal("custom encoded fields escaped")
	}
}
