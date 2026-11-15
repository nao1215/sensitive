package embargozerolog_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/nao1215/embargo"
	embargozerolog "github.com/nao1215/embargo/adapters/zerolog"
)

type domainPassword string

func (domainPassword) String() string               { return "domain-hidden" }
func (domainPassword) MarshalJSON() ([]byte, error) { return json.Marshal("domain-hidden") }
func TestDomainTypeAndJoinedErrors(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindCredential))
	value := domainPassword("opaque-homemade-password")
	failure := fmt.Errorf("request: %w", errors.Join(errors.New("postgres://reader:pretend-password@db.example/orders"), errors.New("token=pretend-token")))
	sink := embargozerolog.NewWriter(&out, scanner)
	logger := zerolog.New(sink)
	logger.Error().Interface("value", value).Stringer("formatted", value).Err(failure).Msg("failure")
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"opaque-homemade-password", "pretend-password", "pretend-token"} {
		if bytes.Contains(out.Bytes(), []byte(secret)) {
			t.Fatal("output leaked")
		}
	}
	if strings.Count(out.String(), "domain-hidden") < 2 {
		t.Fatal("custom methods were not honored")
	}
	if !strings.Contains(out.String(), "db.example/orders") || !strings.Contains(out.String(), "request:") {
		t.Fatal("error context was lost")
	}
}
