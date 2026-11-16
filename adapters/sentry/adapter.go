package embargosentry

import (
	"bytes"
	"encoding/json"

	"github.com/getsentry/sentry-go"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/output"
)

// NewBeforeSend returns a Sentry callback that masks event fields and dynamic sampling context.
// A nil scanner panics. Unencodable events and scanner failures return nil, which
// tells Sentry to drop the event. Attachments are omitted from the copied event;
// use a separate reviewed upload path for them. This callback handles error events,
// not Sentry's separate transaction, log or metric callbacks.
func NewBeforeSend(scanner *embargo.Scanner) func(*sentry.Event, *sentry.EventHint) *sentry.Event {
	output.Require(scanner)
	return func(event *sentry.Event, _ *sentry.EventHint) (safe *sentry.Event) {
		defer func() {
			if recover() != nil {
				safe = nil
			}
		}()
		if event == nil {
			return nil
		}
		raw, err := json.Marshal(struct {
			Event    *sentry.Event     `json:"event"`
			Sampling map[string]string `json:"sampling"`
		}{event, event.GetDynamicSamplingContext()})
		if err != nil {
			return nil
		}
		masked, err := scanner.MaskJSON(raw)
		if err != nil {
			return nil
		}
		var result struct {
			Sampling map[string]string `json:"sampling"`
			Event    sentry.Event      `json:"event"`
		}
		decoder := json.NewDecoder(bytes.NewReader(masked))
		decoder.UseNumber()
		if err := decoder.Decode(&result); err != nil {
			return nil
		}
		if len(result.Sampling) != 0 {
			// A fresh scope restores only the copied sampling context, with no event processors.
			var scope sentry.Scope
			scope.SetPropagationContext(sentry.PropagationContext{DynamicSamplingContext: sentry.DynamicSamplingContext{Entries: result.Sampling, Frozen: true}})
			contexts := result.Event.Contexts
			result.Event.Contexts = nil
			scope.ApplyToEvent(&result.Event, nil, nil)
			result.Event.Contexts = contexts
		}
		return &result.Event
	}
}
