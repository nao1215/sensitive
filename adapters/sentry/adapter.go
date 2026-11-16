package embargosentry

import (
	"bytes"
	"encoding/json"

	"github.com/getsentry/sentry-go"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/output"
)

// NewBeforeSend returns a Sentry callback that masks the event's serialized fields.
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
		raw, err := json.Marshal(event)
		if err != nil {
			return nil
		}
		masked, err := scanner.MaskJSON(raw)
		if err != nil {
			return nil
		}
		var result sentry.Event
		decoder := json.NewDecoder(bytes.NewReader(masked))
		decoder.UseNumber()
		if err := decoder.Decode(&result); err != nil {
			return nil
		}
		return &result
	}
}
