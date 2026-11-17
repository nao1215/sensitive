package embargosentry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"

	"github.com/getsentry/sentry-go"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/output"
	"github.com/nao1215/embargo/internal/saferecord"
)

// NewBeforeSend returns a Sentry callback that masks event fields and dynamic sampling context.
// A nil scanner panics; a nil event stays nil. Encoding/scanner failures, limits
// and cancellation return a diagnostic with time, level, a fixed message and
// contexts.embargo.withheld_attributes, never original keys or values.
// Attachments are omitted from the copied event;
// use a separate reviewed upload path for them. This callback handles error events,
// not Sentry's separate transaction, log or metric callbacks.
func NewBeforeSend(scanner *embargo.Scanner) func(*sentry.Event, *sentry.EventHint) *sentry.Event {
	output.Require(scanner)
	return func(event *sentry.Event, hint *sentry.EventHint) (safe *sentry.Event) {
		if event == nil {
			return nil
		}
		ctx := hintContext(hint)
		var cause error
		complete := false
		defer func() {
			_ = recover() //nolint:errcheck // Never retain panic contents, including panic(nil).
			if !complete {
				safe = withheldEvent(ctx, event, cause)
			}
		}()
		if ctx.Err() != nil {
			return nil
		}
		raw, err := json.Marshal(struct {
			Event    *sentry.Event     `json:"event"`
			Sampling map[string]string `json:"sampling"`
		}{event, event.GetDynamicSamplingContext()})
		if err != nil {
			return nil
		}
		masked, err := scanner.MaskJSONContext(ctx, raw)
		cause = err
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
		restoreSampling(&result.Event, result.Sampling)
		if ctx.Err() != nil {
			return nil
		}
		complete = true
		return &result.Event
	}
}

// hintContext selects the hint's explicit context, then its request context,
// and otherwise a background context.
func hintContext(hint *sentry.EventHint) context.Context {
	switch {
	case hint == nil:
		return context.Background()
	case hint.Context != nil:
		return hint.Context
	case hint.Request != nil:
		return hint.Request.Context()
	default:
		return context.Background()
	}
}

// restoreSampling reattaches masked dynamic sampling entries to event while
// keeping the event's masked contexts out of the scope application.
func restoreSampling(event *sentry.Event, sampling map[string]string) {
	if len(sampling) != 0 {
		// A fresh scope restores only the copied sampling context, with no event processors.
		var scope sentry.Scope
		scope.SetPropagationContext(sentry.PropagationContext{DynamicSamplingContext: sentry.DynamicSamplingContext{Entries: sampling, Frozen: true}})
		contexts := event.Contexts
		event.Contexts = nil
		scope.ApplyToEvent(event, nil, nil)
		event.Contexts = contexts
	}
}

func withheldEvent(ctx context.Context, event *sentry.Event, err error) *sentry.Event {
	count := len(event.Tags)
	for _, fields := range event.Contexts {
		count += len(fields)
	}
	for _, breadcrumb := range event.Breadcrumbs {
		if breadcrumb != nil {
			count += len(breadcrumb.Data)
		}
	}
	count += len(event.GetDynamicSamplingContext())
	level := event.Level
	switch level {
	case sentry.LevelDebug, sentry.LevelInfo, sentry.LevelWarning, sentry.LevelError, sentry.LevelFatal:
	default:
		level = ""
	}
	const identifierBytes = 16
	var identifier [identifierBytes]byte
	if _, readErr := rand.Read(identifier[:]); readErr != nil {
		panic("embargo: event identifier generation failed")
	}
	return &sentry.Event{EventID: sentry.EventID(hex.EncodeToString(identifier[:])), Timestamp: event.Timestamp, Level: level, Message: saferecord.Message(saferecord.Reason(ctx, err)), Contexts: map[string]sentry.Context{"embargo": {"withheld_attributes": count}}}
}
