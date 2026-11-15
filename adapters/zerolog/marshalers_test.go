package embargozerolog_test

import (
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"

	"github.com/nao1215/embargo"
	embargozerolog "github.com/nao1215/embargo/adapters/zerolog"
	"github.com/nao1215/embargo/embargotest"
)

type objectCanary struct{ value string }

func (o objectCanary) MarshalZerologObject(event *zerolog.Event) {
	event.Str("token", o.value).Str("email", "alice@example.com")
}

//nolint:goconst // Keep literal expected bytes beside the real logger calls.
func TestObjectArrayAndRawJSONFields(t *testing.T) {
	t.Parallel()
	canary := "public-marshaler-canary"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail), embargo.WithDetector(literal{value: []byte(canary)}))
	r := embargotest.New(t, embargotest.WithCanary([]byte(canary)), embargotest.WithScanner(scanner))
	writer := embargozerolog.NewWriter(r.Writer("out"), scanner)
	logger := zerolog.New(writer).With().Object("pre", objectCanary{value: canary}).Logger()
	//nolint:errchkjson // Keep the explicit encoding error check required by strict errcheck.
	raw, err := json.Marshal(map[string]string{"token": canary})
	if err != nil {
		t.Fatal(err)
	}
	logger.Info().Object("object", objectCanary{value: canary}).Array("array", zerolog.Arr().Str(canary).Object(objectCanary{value: canary})).RawJSON("raw", raw).Msg("event")
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	r.ExpectJSON("out", []string{"object"}, map[string]string{"token": "[REDACTED]", "email": "[REDACTED]"}, 1)
	if !r.Check() {
		t.Fatal("custom encoded fields escaped")
	}
}
