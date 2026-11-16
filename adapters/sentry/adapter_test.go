package embargosentry_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strconv"
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

const testDSN = "https://public@example.com/1"

func (*eventTransport) Configure(sentry.ClientOptions) {}

func (t *eventTransport) SendEvent(event *sentry.Event) { t.events = append(t.events, event) }

func (*eventTransport) Flush(time.Duration) bool { return true }

func (*eventTransport) Close() {}

func (*eventTransport) FlushWithContext(context.Context) bool { return true }

func TestBeforeSendThroughSentryClient(t *testing.T) {
	t.Parallel()
	transport := &eventTransport{}
	client, err := sentry.NewClient(sentry.ClientOptions{Dsn: testDSN, Transport: transport, BeforeSend: embargosentry.NewBeforeSend(embargo.NewScanner())})
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
		if safe := hook(event, nil); safe == nil || safe.Message != "embargo: record withheld (masking error)" {
			t.Fatal("invalid event reached transport")
		}
	}
}

func TestOversizedEventIsDropped(t *testing.T) {
	t.Parallel()
	event := sentry.NewEvent()
	event.Message = strings.Repeat("x", 1<<20)
	if safe := embargosentry.NewBeforeSend(embargo.NewScanner())(event, nil); safe == nil || safe.Message != "embargo: record withheld (size limit)" {
		t.Fatal("oversized event was not withheld")
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
			client, err := sentry.NewClient(sentry.ClientOptions{Dsn: testDSN, Transport: transport, BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
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

type cancelingScan struct {
	cancel context.CancelFunc
	calls  int
}

func (d *cancelingScan) Scan([]byte) []embargo.Finding { d.calls++; d.cancel(); return nil }

func TestSentryContextCancellation(t *testing.T) {
	t.Parallel()
	for _, alreadyCanceled := range []bool{true, false} {
		t.Run(strconv.FormatBool(alreadyCanceled), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if alreadyCanceled {
				cancel()
			}
			detector := &cancelingScan{cancel: cancel}
			scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(detector))
			event := sentry.NewEvent()
			event.Message = "public"
			got := embargosentry.NewBeforeSend(scanner)(event, &sentry.EventHint{Context: ctx})
			want := 1
			if alreadyCanceled {
				want = 0
			}
			if got == nil || got.Message != "embargo: record withheld (canceled)" || detector.calls != want {
				t.Fatalf("forwarded=%t scans=%d want=%d", got != nil, detector.calls, want)
			}
		})
	}
}

func TestBeforeSendRequestCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	detector := &cancelingScan{cancel: cancel}
	event := sentry.NewEvent()
	hint := &sentry.EventHint{Request: httptest.NewRequestWithContext(ctx, "GET", "/", nil)}
	if got := embargosentry.NewBeforeSend(embargo.NewScanner(embargo.WithDetector(detector)))(event, hint); got == nil || got.Message != "embargo: record withheld (canceled)" || detector.calls != 0 {
		t.Fatal("canceled request scanned or sent")
	}
}

func TestBeforeSendMaskedKeyCollision(t *testing.T) {
	t.Parallel()
	event := sentry.NewEvent()
	event.Contexts["extra"] = sentry.Context{"a@example.com": float64(4111111111111111), "z@example.com": 7}
	event.Tags["a@example.com"] = "4111111111111111"
	event.Tags["z@example.com"] = "retained"
	safe := embargosentry.NewBeforeSend(embargo.NewScanner())(event, nil)
	if safe == nil || safe.Contexts["extra"][sentryMarker] != json.Number("7") || safe.Tags[sentryMarker] != "retained" {
		t.Fatalf("collision changed safe values: %v", safe)
	}
}

func sentryScalingCall(size int) func() {
	hook := embargosentry.NewBeforeSend(embargo.NewScanner(embargo.WithAll()))
	event := sentry.NewEvent()
	event.Message = strings.Repeat("x", size)
	return func() { hook(event, nil) }
}

//nolint:paralleltest // Measure the delta without concurrent allocations from other tests.
func TestHookAllocationBudget(t *testing.T) {
	const size = 64 << 10
	call := sentryScalingCall(size)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	call()
	runtime.ReadMemStats(&after)
	if after.TotalAlloc-before.TotalAlloc > 128*size+1<<20 {
		t.Fatal("Sentry hook allocation amplification")
	}
}

func BenchmarkHookScaling(b *testing.B) {
	for _, size := range []int{1 << 10, 16 << 10, 256 << 10, 1 << 20, 16 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			call := sentryScalingCall(size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				call()
			}
		})
	}
}

type auditPanicDetector struct{}

func (auditPanicDetector) Scan([]byte) []embargo.Finding { panic("planted-panic") }
func TestWithheldRecord(t *testing.T) {
	t.Parallel()
	for _, reason := range []string{"masking error", "size limit", "canceled"} {
		t.Run(reason, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			scanner := embargo.NewScanner()
			value := "planted-value"
			if reason == "masking error" {
				scanner = embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(auditPanicDetector{}))
			}
			if reason == "size limit" {
				value += strings.Repeat("x", 1<<20)
			}
			if reason == "canceled" {
				cancel()
			}
			event := sentry.NewEvent()
			event.Timestamp = time.Unix(7, 0)
			event.Level = sentry.LevelWarning
			event.Message = "planted-message"
			event.Tags = map[string]string{"planted-key": value}
			after := embargosentry.NewBeforeSend(scanner)(event, &sentry.EventHint{Context: ctx})
			if after == nil {
				t.Fatal("missing fallback")
			}
			if after.Timestamp != event.Timestamp || after.Level != event.Level || after.Message != "embargo: record withheld ("+reason+")" {
				t.Fatal("wrong fallback metadata")
			}
			raw, err := json.Marshal(after)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "planted") || after.Contexts["embargo"]["withheld_attributes"] != 1 {
				t.Fatal(string(raw))
			}
		})
	}
}

func TestWithheldRecordThroughClient(t *testing.T) {
	t.Parallel()
	transport := &eventTransport{}
	client, err := sentry.NewClient(sentry.ClientOptions{Dsn: testDSN, Transport: transport, BeforeSend: embargosentry.NewBeforeSend(embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(auditPanicDetector{})))})
	if err != nil {
		t.Fatal(err)
	}
	event := sentry.NewEvent()
	event.EventID = "planted-id"
	event.Message = "planted-message"
	event.Tags["planted-key"] = "planted-value"
	id := client.CaptureEvent(event, nil, sentry.NewScope())
	if id == nil || len(*id) != 32 || *id == event.EventID || len(transport.events) != 1 {
		t.Fatalf("diagnostic lacks a usable event ID: %v", id)
	}
	raw, err := json.Marshal(transport.events[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "planted") {
		t.Fatal("diagnostic retained original data")
	}
}
