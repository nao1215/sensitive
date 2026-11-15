package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/embargotest"
)

const sentryOutputExcerpt = `"signing":{"key":"[REDACTED]"}`

// bufferedTransport is a sentry.Transport that holds events until Flush and
// then writes the JSON the real SDK would send, one event per line. Holding
// until Flush mirrors HTTPTransport, so a missing Flush loses the events.
type bufferedTransport struct {
	w      io.Writer
	events []*sentry.Event
	mu     sync.Mutex
}

func (b *bufferedTransport) Configure(sentry.ClientOptions) {}
func (b *bufferedTransport) Close()                         {}
func (b *bufferedTransport) SendEvent(event *sentry.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, event)
}

func (b *bufferedTransport) Flush(time.Duration) bool {
	return b.FlushWithContext(context.Background())
}

func (b *bufferedTransport) FlushWithContext(context.Context) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	encoder := json.NewEncoder(b.w)
	for _, event := range b.events {
		if err := encoder.Encode(event); err != nil {
			return false
		}
	}
	b.events = nil
	return true
}

// sentryEvent uses an application-owned code and the SDK's argument-free stack representation.
func sentryEvent(d failure) *sentry.Event {
	stack := sentry.NewStacktrace()
	event := sentry.NewEvent()
	event.Level = sentry.LevelError
	event.Message = d.message
	event.Tags = map[string]string{"code": d.code}
	event.Exception = []sentry.Exception{{Type: d.code, Value: d.message, Stacktrace: stack}}
	return event
}

//nolint:gocognit,goconst // Keep the expected outputs and failure modes together in this acceptance matrix.
func checkSentryAcceptance(t *testing.T) {
	t.Helper()
	for _, mode := range []string{"safe", "raw-error", "raw-recover", "raw-context", "missing-flush", "regressed"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			probe := &observationTB{TB: t}
			r := embargotest.New(probe)
			d := signingFailed()
			transport := &bufferedTransport{w: r.Writer("sentry")}
			client, err := sentry.NewClient(sentry.ClientOptions{Transport: transport, AttachStacktrace: true})
			if err != nil {
				t.Fatal("client setup failed")
			}
			// The client starts batch goroutines; Close stops them so goleak
			// sees none left after the test.
			defer client.Close()
			hub := sentry.NewHub(client, sentry.NewScope())
			key := embargo.NewSecret(string(r.Canary()))
			// A Secret in scope data is marshaled with the event; the context
			// path must print the marker, not the key.
			hub.Scope().SetContext("signing", sentry.Context{"key": key})

			switch mode {
			case "raw-error":
				hub.CaptureException(fmt.Errorf("request: %w", errors.Join(errors.New("database unavailable"), errors.New("token="+key.Reveal()))))
			case "raw-recover":
				hub.Recover("signing failed: " + key.Reveal())
			case "raw-context":
				hub.Scope().SetContext("signing_raw", sentry.Context{"key": key.Reveal()})
				hub.CaptureEvent(sentryEvent(d))
			case "regressed":
				hub.CaptureEvent(sentryEvent(withheld()))
			default:
				hub.CaptureEvent(sentryEvent(d))
			}
			if mode != "missing-flush" && !hub.Flush(time.Second) {
				t.Fatal("flush failed")
			}

			r.Expect("sentry", func(data []byte) bool {
				if mode == "raw-error" {
					return json.Valid(data) && bytes.Contains(data, []byte("request:")) && bytes.Contains(data, r.Canary())
				}
				if !bytes.Contains(data, []byte(sentryOutputExcerpt)) {
					return false
				}
				var event struct {
					Message   string                    `json:"message"`
					Tags      map[string]string         `json:"tags"`
					Contexts  map[string]map[string]any `json:"contexts"`
					Exception []struct {
						Type       string `json:"type"`
						Value      string `json:"value"`
						Stacktrace struct {
							Frames []struct {
								Function string `json:"function"`
								Lineno   int    `json:"lineno"`
							} `json:"frames"`
						} `json:"stacktrace"`
					} `json:"exception"`
				}
				if json.Unmarshal(data, &event) != nil || len(event.Exception) != 1 {
					return false
				}

				ex := event.Exception[0]
				frames := ex.Stacktrace.Frames
				return ex.Type == d.code && ex.Value == d.message && event.Tags["code"] == d.code &&
					event.Contexts["signing"]["key"] == "[REDACTED]" &&
					len(frames) > 0 && frames[len(frames)-1].Function != "" && frames[len(frames)-1].Lineno > 0
			})
			if r.Check() != (mode == "safe") {
				t.Fatalf("Sentry detector returned wrong verdict: %v", probe.messages)
			}
			if mode == "raw-error" {
				messages := strings.Join(probe.messages, "\n")
				if !strings.Contains(messages, "the fake secret appeared") || strings.Contains(messages, "content expectation") {
					t.Fatal("wrapped error must fail for a leak, not a missing export", probe.messages)
				}
			}
			probe.finish()
		})
	}
}
