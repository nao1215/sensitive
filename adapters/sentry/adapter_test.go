package embargosentry_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/nao1215/embargo"
	embargosentry "github.com/nao1215/embargo/adapters/sentry"
)

const (
	sentryPassword = "synthetic-password"
	sentryMarker   = "[REDACTED]"
)

type eventTransport struct{ events []*sentry.Event }

func (*eventTransport) Configure(sentry.ClientOptions)        {}
func (t *eventTransport) SendEvent(event *sentry.Event)       { t.events = append(t.events, event) }
func (*eventTransport) Flush(time.Duration) bool              { return true }
func (*eventTransport) Close()                                {}
func (*eventTransport) FlushWithContext(context.Context) bool { return true }

func TestBeforeSendThroughSentryClient(t *testing.T) {
	t.Parallel()
	transport := &eventTransport{}
	client, err := sentry.NewClient(sentry.ClientOptions{Dsn: "https://public@example.com/1", Transport: transport, BeforeSend: embargosentry.NewBeforeSend(embargo.NewScanner())})
	if err != nil {
		t.Fatal(err)
	}
	event := sentry.NewEvent()
	event.Message = "alice@example.com failed"
	event.Exception = []sentry.Exception{{Type: "checkout.Failure", Value: "password=exception-secret", Stacktrace: &sentry.Stacktrace{Frames: []sentry.Frame{{Function: "checkout", Filename: "worker.go"}}}}}
	event.Contexts = map[string]sentry.Context{"details": {"password": sentryPassword, "count": 7}}
	event.Request = &sentry.Request{URL: "https://example.com/login?token=synthetic-query", Headers: map[string]string{"Authorization": "Bearer synthetic-session"}}
	event.Breadcrumbs = []*sentry.Breadcrumb{{Message: "token=synthetic-breadcrumb"}}
	client.CaptureEvent(event, nil, sentry.NewScope())
	if len(transport.events) != 1 {
		t.Fatal("expected one transmitted event")
	}
	data, err := json.Marshal(transport.events[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"alice@example.com", sentryPassword, "synthetic-query", "synthetic-session", "synthetic-breadcrumb", "exception-secret"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("sent %s", secret)
		}
	}
	if len(transport.events[0].Exception) != 1 || transport.events[0].Exception[0].Value != "password=[REDACTED]" || transport.events[0].Exception[0].Stacktrace.Frames[0].Function != "checkout" {
		t.Fatal("exception or stack frame lost during reconstruction")
	}
	if event.Contexts["details"]["password"] != sentryPassword || !strings.Contains(string(data), `"count":7`) {
		t.Fatal("event copy changed types or mutated input")
	}
}

type failingEventValue struct{}

func (*failingEventValue) MarshalJSON() ([]byte, error) { panic("private event panic") }

func TestBeforeSendSuppressesInvalidEvents(t *testing.T) {
	t.Parallel()
	hook := embargosentry.NewBeforeSend(embargo.NewScanner())
	if hook(nil, nil) != nil {
		t.Fatal("nil event became output")
	}
	for _, value := range []any{make(chan int), &failingEventValue{}} {
		event := sentry.NewEvent()
		event.Contexts = map[string]sentry.Context{"details": {"value": value}}
		if hook(event, nil) != nil {
			t.Fatal("invalid event reached transport")
		}
	}
}

func TestOversizedEventIsDropped(t *testing.T) {
	t.Parallel()
	event := sentry.NewEvent()
	event.Message = strings.Repeat("x", 1<<20)
	if safe := embargosentry.NewBeforeSend(embargo.NewScanner())(event, nil); safe != nil {
		t.Fatal("oversized event reached transport")
	}
}

func TestClientPreservesAndMasksDynamicSamplingContext(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ value, want string }{{"cart", "cart"}, {"alice@example.com", sentryMarker}} {
		t.Run(tc.value, func(t *testing.T) {
			t.Parallel()
			transport := &eventTransport{}
			hook := embargosentry.NewBeforeSend(embargo.NewScanner())
			var before map[string]string
			client, err := sentry.NewClient(sentry.ClientOptions{Dsn: "https://public@example.com/1", Transport: transport, BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
				before = event.GetDynamicSamplingContext()
				return hook(event, hint)
			}})
			if err != nil {
				t.Fatal(err)
			}
			scope := sentry.NewScope()
			entries := map[string]string{"transaction": tc.value, "sample_rate": "0.25"}
			scope.SetPropagationContext(sentry.PropagationContext{DynamicSamplingContext: sentry.DynamicSamplingContext{Entries: entries, Frozen: true}})
			event := sentry.NewEvent()
			event.Message = "password=private-password"
			event.Attachments = []*sentry.Attachment{{Filename: "private.txt", Payload: []byte("private attachment")}}
			client.CaptureEvent(event, nil, scope)
			if len(transport.events) != 1 {
				t.Fatal("missing event")
			}
			got := transport.events[0]
			want := map[string]string{"transaction": tc.want, "sample_rate": "0.25"}
			if !reflect.DeepEqual(before, entries) || !reflect.DeepEqual(got.GetDynamicSamplingContext(), want) {
				t.Fatalf("sampling context before=%v after=%v", before, got.GetDynamicSamplingContext())
			}
			if len(got.Attachments) != 0 || got.Message != "password=[REDACTED]" || event.Message != "password=private-password" {
				t.Fatal("event masking changed attachment or copy behavior")
			}
		})
	}
}

func TestContextAndTagOriginalKeyContext(t *testing.T) {
	t.Parallel()
	event := sentry.NewEvent()
	event.Timestamp = time.Time{}
	event.Contexts["extra"] = sentry.Context{}
	for _, fixture := range []struct {
		value any
		key   string
	}{{731, "cvv"}, {"opaque-client-value", "client_secret"}, {"12/29", "expiry"}} {
		event.Contexts["extra"][fixture.key] = fixture.value
		event.Tags[fixture.key] = fmt.Sprint(fixture.value)
	}
	safe := embargosentry.NewBeforeSend(embargo.NewScanner())(event, nil)
	if safe == nil {
		t.Fatal("missing event")
	}
	for key := range event.Tags {
		if safe.Tags[key] != sentryMarker || safe.Contexts["extra"][key] != sentryMarker {
			t.Errorf("field %s was not masked", key)
		}
	}
}
