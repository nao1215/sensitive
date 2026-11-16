package embargo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/saferecord"
)

func TestHTTPHandlerMasksLogsAndPreservesExchange(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	scanner := embargo.NewScanner(embargo.WithSensitiveKeys("recovery_code"))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer opaque-auth" || r.URL.Query().Get("recovery_code") != "opaque-query" {
			t.Error("middleware changed service input")
		}
		w.Header().Set("Set-Cookie", "session=opaque-cookie")
		w.Header().Set("Location", "/finish?recovery_code=opaque-redirect&user=customer%40example.com")
		w.Header().Set("X-Public", "retained")
		w.WriteHeader(http.StatusFound)
		if _, err := io.WriteString(w, "public response"); err != nil {
			t.Error(err)
		}
	})
	server := httptest.NewServer(embargo.NewHTTPHandler(handler, logger, scanner))
	defer server.Close()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/login?recovery_code=opaque-query", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer opaque-auth")
	request.Header.Set("Cookie", "session=opaque-request-cookie")
	request.Header.Set("Recovery-Code", "opaque-custom")
	client := server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusFound || string(body) != "public response" || !strings.Contains(response.Header.Get("Location"), "opaque-redirect") {
		t.Fatal("middleware changed response")
	}
	for _, secret := range []string{"opaque-auth", "opaque-query", "opaque-redirect", "opaque-cookie", "opaque-request-cookie", "opaque-custom", "customer@example.com", "customer%40example.com"} {
		if strings.Contains(output.String(), secret) {
			t.Errorf("log retained %s", secret)
		}
	}
	if !strings.Contains(output.String(), "retained") || !strings.Contains(output.String(), "302") {
		t.Fatal(output.String())
	}
}

func TestHTTPHandlerRejectsTypedNilHandler(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("nil handler accepted")
		}
	}()
	var next http.HandlerFunc
	embargo.NewHTTPHandler(next, slog.New(slog.DiscardHandler), embargo.NewScanner())
}

func TestHTTPHandlerWriterControlsAndHeaderSnapshot(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	handler := embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Phase", "interim")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("X-Phase", "final")
		w.WriteHeader(http.StatusAccepted)
		w.Header().Set("X-Phase", "changed after headers")
		w.WriteHeader(http.StatusForbidden)
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error(err)
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("missing Flusher")
		}
		flusher.Flush()
		pusher, ok := w.(http.Pusher)
		if !ok {
			t.Fatal("missing Pusher")
		}
		if err := pusher.Push("/static", nil); !errors.Is(err, http.ErrNotSupported) {
			t.Error(err)
		}
		if _, _, err := http.NewResponseController(w).Hijack(); !errors.Is(err, http.ErrNotSupported) {
			t.Error(err)
		}
	}), slog.New(slog.NewJSONHandler(&logs, nil)), embargo.NewScanner())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody))
	if !response.Flushed || !strings.Contains(logs.String(), `"status":202`) || !strings.Contains(logs.String(), `"X-Phase":["final"]`) {
		t.Fatal(logs.String())
	}
}

func TestHTTPHandlerEmptyResponseAndInvalidTarget(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	handler := embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Location", "://opaque") }), slog.New(slog.NewJSONHandler(&logs, nil)), embargo.NewScanner())
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://reader:opaque@example.com/?bad;query", http.NoBody))
	if strings.Contains(logs.String(), "opaque") || !strings.Contains(logs.String(), "record withheld (masking error)") {
		t.Fatal(logs.String())
	}
}

type failingHTTPDetector struct{}

func (*failingHTTPDetector) Scan([]byte) []embargo.Finding { panic("private panic payload") }

func TestHTTPHandlerScannerFailureDoesNotChangeResponse(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(&failingHTTPDetector{}))
	handler := embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), slog.New(slog.NewJSONHandler(&logs, nil)), scanner)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody))
	if response.Code != http.StatusNoContent || !strings.Contains(logs.String(), "record withheld (masking error)") {
		t.Fatal("logging failure changed service response or lost audit record")
	}
}

type controlWriter struct {
	header   http.Header
	deadline bool
	pushed   bool
}

func (w *controlWriter) Header() http.Header { return w.header }

func (*controlWriter) WriteHeader(int) {}

func (*controlWriter) Write(p []byte) (int, error) { return len(p), nil }

func (w *controlWriter) SetWriteDeadline(time.Time) error { w.deadline = true; return nil }

func (w *controlWriter) Push(string, *http.PushOptions) error { w.pushed = true; return nil }

func TestHTTPHandlerForwardsControllerAndPush(t *testing.T) {
	t.Parallel()
	writer := &controlWriter{header: make(http.Header)}
	handler := embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(w).SetWriteDeadline(time.Time{}); err != nil {
			t.Error(err)
		}
		pusher, ok := w.(http.Pusher)
		if !ok {
			t.Fatal("missing Push")
		}
		if err := pusher.Push("/asset", nil); err != nil {
			t.Error(err)
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("missing Flush")
		}
		flusher.Flush()
		if _, err := w.Write([]byte("body")); err != nil {
			t.Error(err)
		}
	}), slog.New(slog.DiscardHandler), embargo.NewScanner())
	handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody))
	if !writer.deadline || !writer.pushed {
		t.Fatal("underlying capability lost")
	}
}

func TestHTTPHandlerImplicitWrite(t *testing.T) {
	t.Parallel()
	handler := embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte("hello")); err != nil {
			t.Error(err)
		}
	}), slog.New(slog.DiscardHandler), embargo.NewScanner())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody))
	if response.Result().Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatal("implicit write lost Content-Type detection")
	}
	if response.Code != http.StatusOK || response.Body.String() != "hello" {
		t.Fatal("implicit status or body changed")
	}
}

func TestHTTPUnsupportedFlushLeavesStatusUncommitted(t *testing.T) {
	t.Parallel()
	response := httptest.NewRecorder()
	writer := struct{ http.ResponseWriter }{response}
	handler := embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(w).Flush(); !errors.Is(err, http.ErrNotSupported) {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusTeapot)
	}), slog.New(slog.DiscardHandler), embargo.NewScanner())
	handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody))
	if response.Code != http.StatusTeapot {
		t.Fatalf("unsupported flush committed status %d", response.Code)
	}
}

func TestHTTPImplicitFlushSnapshotsCommittedHeaders(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	handler := embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Phase", "flushed")
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("X-Phase", "too late")
	}), slog.New(slog.NewJSONHandler(&logs, nil)), embargo.NewScanner())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody))
	if !response.Flushed || response.Code != http.StatusOK || !strings.Contains(logs.String(), `"X-Phase":["flushed"]`) || !strings.Contains(logs.String(), `"status":200`) {
		t.Fatal("implicit flush lost the committed response snapshot")
	}
}

func TestHTTPOriginalKeyContext(t *testing.T) {
	t.Parallel()
	for _, fixture := range []struct{ key, value string }{{"cvv", "731"}, {"client_secret", "opaque-client-value"}, {"bank account", "12345678"}, {"expiry", "12/29"}} {
		t.Run(fixture.key, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			query := url.Values{fixture.key: {fixture.value}}.Encode()
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/pay?"+query, http.NoBody)
			request.Header[fixture.key] = []string{fixture.value}
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get(fixture.key) != fixture.value || r.Header[fixture.key][0] != fixture.value {
					t.Error("input changed")
				}
				w.Header().Set("Location", "/return?"+query)
				w.Header()[fixture.key] = []string{fixture.value}
				w.WriteHeader(http.StatusFound)
			})
			embargo.NewHTTPHandler(next, slog.New(slog.NewJSONHandler(&out, &slog.HandlerOptions{ReplaceAttr: omitRecordTime})), embargo.NewScanner()).ServeHTTP(httptest.NewRecorder(), request)
			if out.Len() == 0 || strings.Contains(out.String(), fixture.value) || strings.Contains(out.String(), url.QueryEscape(fixture.value)) {
				t.Fatalf("context lost: %s", out.String())
			}
		})
	}
}

func TestHTTPContextCancellation(t *testing.T) {
	t.Parallel()
	for _, alreadyCanceled := range []bool{true, false} {
		t.Run(strconv.FormatBool(alreadyCanceled), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if alreadyCanceled {
				cancel()
			}
			var out bytes.Buffer
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { cancel(); w.WriteHeader(http.StatusAccepted) })
			request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/pay?email=alice%40example.com&token=planted-query", http.NoBody)
			request.Header.Set("Authorization", "planted-header")
			response := httptest.NewRecorder()
			embargo.NewHTTPHandler(next, slog.New(slog.NewJSONHandler(&out, nil)), embargo.NewScanner()).ServeHTTP(response, request)
			if response.Code != http.StatusAccepted {
				t.Fatal("response changed")
			}
			assertHTTPAccessRecord(t, out.Bytes(), "/pay?email=[REDACTED]&token=[REDACTED]")
		})
	}
}

func assertHTTPAccessRecord(t *testing.T, data []byte, target string) {
	t.Helper()
	const marker = "[REDACTED]"
	var record struct {
		RequestHeaders map[string]any `json:"request_headers"`
		Msg            string         `json:"msg"`
		Method         string         `json:"method"`
		Target         string         `json:"target"`
		Status         int            `json:"status"`
	}
	// Unmarshal rejects trailing records as well as missing or malformed JSON.
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record.Msg != "http request" || record.Method != http.MethodGet || record.Target != target || record.Status != http.StatusAccepted || record.RequestHeaders["Authorization"] != marker {
		t.Fatalf("wrong access record: %s", data)
	}
}

func assertHTTPWithheld(t *testing.T, data []byte, reason string) {
	t.Helper()
	assertWithheldJSON(t, data, reason, 6)
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if len(record) != 6 || record["status"] != float64(http.StatusAccepted) || record["duration"] == nil {
		t.Fatalf("unsafe or incomplete fallback: %s", data)
	}
}

func httpScalingCall(tb testing.TB, size int) func() {
	tb.Helper()
	//nolint:sloglint // Measure the JSON output boundary even though the bytes are discarded.
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handler := embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), logger, embargo.NewScanner(embargo.WithAll()))
	request := httptest.NewRequestWithContext(tb.Context(), http.MethodGet, "/?public="+strings.Repeat("x", size), http.NoBody)
	return func() { handler.ServeHTTP(httptest.NewRecorder(), request) }
}

//nolint:paralleltest // Allocation accounting must not overlap other tests.
func TestHookAllocationBudget(t *testing.T) {
	const size = 64 << 10
	call := httpScalingCall(t, size)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	call()
	runtime.ReadMemStats(&after)
	if after.TotalAlloc-before.TotalAlloc > 128*size+1<<20 {
		t.Fatal("HTTP hook allocation amplification")
	}
}

func BenchmarkHookScaling(b *testing.B) {
	for _, size := range []int{1 << 10, 16 << 10, 256 << 10, 1 << 20, 16 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			call := httpScalingCall(b, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				call()
			}
		})
	}
}

func TestHTTPWithheldRecord(t *testing.T) {
	t.Parallel()
	for _, reason := range []string{maskingReason, sizeReason, canceledReason} {
		t.Run(reason, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			scanner := embargo.NewScanner()
			if reason == maskingReason {
				scanner = embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(&failingHTTPDetector{}))
			}
			var out bytes.Buffer
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if reason == canceledReason {
					cancel()
				}
				w.WriteHeader(http.StatusAccepted)
			})
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/pay?token=planted-query", http.NoBody)
			req.Header.Set("Authorization", "planted-header")
			if reason == sizeReason {
				req.Header.Set("X-Large", strings.Repeat("x", 1<<20))
			}
			embargo.NewHTTPHandler(next, slog.New(slog.NewJSONHandler(&out, nil)), scanner).ServeHTTP(httptest.NewRecorder(), req)
			if reason == canceledReason {
				assertHTTPAccessRecord(t, out.Bytes(), "/pay?token=[REDACTED]")
			} else {
				assertHTTPWithheld(t, out.Bytes(), reason)
			}
		})
	}
}

type budgetDetector struct {
	cancel context.CancelFunc
	calls  int
}

func (d *budgetDetector) Scan([]byte) []embargo.Finding {
	d.calls++
	if d.cancel != nil {
		d.cancel()
	}
	return nil
}

func TestHTTPMaskingBudgetEmitsFallback(t *testing.T) {
	t.Parallel()
	detector := &budgetDetector{}
	clockCalls := 0
	ctx := saferecord.WithAccessPolicy(t.Context(), saferecord.AccessPolicy{
		Now: func() time.Time { clockCalls++; return time.Unix(7, 0).Add(time.Duration(clockCalls) * time.Second) },
		Timeout: func(parent context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
			if budget != 100*time.Millisecond || parent.Err() != nil {
				t.Error("wrong detached budget")
			}
			bounded, cancel := context.WithCancel(parent)
			detector.cancel = cancel
			return bounded, cancel
		},
	})
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(detector))
	var out bytes.Buffer
	handler := embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }), slog.New(slog.NewJSONHandler(&out, nil)), scanner)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequestWithContext(ctx, http.MethodGet, "/?token=planted-query", http.NoBody))
	assertHTTPWithheld(t, out.Bytes(), canceledReason)
	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["duration"] != float64(time.Second) || detector.calls != 1 || response.Code != http.StatusAccepted {
		t.Fatal("budget changed outcome or duration")
	}
}

func TestHTTPMalformedHeaderTargetWithholdsWholeRecord(t *testing.T) {
	t.Parallel()
	for _, location := range []string{"://planted-secret", "/?bad;planted-secret"} {
		for _, responseHeader := range []bool{false, true} {
			t.Run(location+strconv.FormatBool(responseHeader), func(t *testing.T) {
				t.Parallel()
				var out bytes.Buffer
				next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if responseHeader {
						w.Header().Set("Location", location)
					}
					w.WriteHeader(http.StatusAccepted)
				})
				handler := embargo.NewHTTPHandler(next, slog.New(slog.NewJSONHandler(&out, nil)), embargo.NewScanner())
				request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
				if !responseHeader {
					request.Header.Set("Location", location)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				assertHTTPWithheld(t, out.Bytes(), maskingReason)
				if response.Code != http.StatusAccepted {
					t.Fatal("diagnosing a header changed the service response")
				}
			})
		}
	}
}

func TestHTTPDiagnosticSinkFailurePreservesResponse(t *testing.T) {
	t.Parallel()
	sink := &inspectingHandler{enabled: true, err: io.ErrClosedPipe}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
	handler := embargo.NewHTTPHandler(next, slog.New(sink), embargo.NewScanner())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/?bad;planted-secret", http.NoBody))
	if response.Code != http.StatusAccepted || sink.handled != 1 || sink.record.Message != "embargo: record withheld (masking error)" {
		t.Fatal("sink failure changed the response or prevented the diagnostic attempt")
	}
}

func noTime(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return a
}

func httpLog(t *testing.T, target string, reqHeader http.Header) string {
	t.Helper()
	var out bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&out, &slog.HandlerOptions{ReplaceAttr: noTime}))
	h := embargo.NewHTTPHandler(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}), logger, embargo.NewScanner())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, http.NoBody)
	maps.Copy(req.Header, reqHeader)
	h.ServeHTTP(httptest.NewRecorder(), req)
	return strings.TrimSpace(out.String())
}

func TestOutputQueryKeyReencoding(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner()
	for _, key := range []string{"4111%201111%201111%201111", "090%201234%205678", "1234%205678%209018", "DE89%203704%200044%200532%200130%2000"} {
		for _, suffix := range []string{"", "=public"} {
			target := "/search?" + key + suffix
			want := embargo.Mask(target, scanner.ScanString(target))
			if want == target {
				t.Fatalf("scanner control failed: %q", target)
			}
			var record map[string]any
			if err := json.Unmarshal([]byte(httpLog(t, target, nil)), &record); err != nil {
				t.Fatal(err)
			}
			if record["target"] != want {
				t.Fatalf("scanner masked %q but access target is %q", want, record["target"])
			}
		}
	}
}

func TestOutputProxyAuthorization(t *testing.T) {
	t.Parallel()
	got := httpLog(t, "/", http.Header{"Proxy-Authorization": {"Basic dXNlcjpodW50ZXIy"}, "Authorization": {"Basic dXNlcjpodW50ZXIy"}})
	t.Logf("%s", got)
	if strings.Contains(got, "dXNlcjpodW50ZXIy") {
		t.Errorf("Basic credentials reached the access log")
	}
}

func TestHTTPSinglePassQuery(t *testing.T) {
	t.Parallel()
	scanner := embargo.NewScanner()
	for _, input := range []string{"cvv: " + strings.Repeat("a", 60) + "@example.com 123", "bank account: " + strings.Repeat("a", 60) + "@example.com 2026", "exp " + strings.Repeat("a", 60) + "@example.com 12/29"} {
		//nolint:errchkjson // Match the explicit JSON error boundaries in the test.
		raw, err := json.Marshal(map[string]string{"detail": input})
		if err != nil {
			t.Fatal(err)
		}
		expected, err := scanner.MaskJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		var values map[string]string
		if err := json.Unmarshal(expected, &values); err != nil {
			t.Fatal(err)
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(httpLog(t, "/health?detail="+url.QueryEscape(input), http.Header{"Detail": {input}})), &record); err != nil {
			t.Fatal(err)
		}
		// Query values are decoded before scanning and are never encoded again.
		if record["target"] != "/health?detail="+values["detail"] {
			t.Fatalf("single pass target=%q, got=%q", values["detail"], record["target"])
		}
		headers, ok := record["request_headers"].(map[string]any)
		if !ok {
			t.Fatal("missing headers")
		}
		detail, ok := headers["Detail"].([]any)
		if !ok || len(detail) != 1 || detail[0] != values["detail"] {
			t.Fatalf("header scanned more than once: %v", headers)
		}
	}
}

func TestHTTPPanicStatus(t *testing.T) {
	t.Parallel()
	for _, panicValue := range []any{"planted-panic", http.ErrAbortHandler} {
		for _, status := range []int{0, http.StatusAccepted} {
			var out bytes.Buffer
			handler := embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if status != 0 {
					w.WriteHeader(status)
				}
				panic(panicValue)
			}), slog.New(slog.NewJSONHandler(&out, nil)), embargo.NewScanner())
			func() {
				defer func() {
					if got := recover(); got != panicValue {
						t.Errorf("panic changed: %v", got)
					}
				}()
				handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody))
			}()
			var record map[string]any
			if err := json.Unmarshal(out.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if record["status"] != float64(status) {
				t.Fatalf("panic status=%v, want=%d", record["status"], status)
			}
			if strings.Contains(out.String(), "planted") {
				t.Fatal("panic content retained")
			}
		}
	}
}

func TestHTTPOrdinaryRequestHasNoDetachedDeadline(t *testing.T) {
	t.Parallel()
	detector := &budgetDetector{}
	ctx := saferecord.WithAccessPolicy(t.Context(), saferecord.AccessPolicy{Timeout: func(context.Context, time.Duration) (context.Context, context.CancelFunc) {
		t.Fatal("ordinary request used detached budget")
		return nil, nil
	}})
	var out bytes.Buffer
	handler := embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }), slog.New(slog.NewJSONHandler(&out, nil)), embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(detector)))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(ctx, http.MethodGet, "/safe", http.NoBody))
	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["msg"] != "http request" || record["status"] != float64(http.StatusAccepted) {
		t.Fatalf("ordinary record lost: %s", out.String())
	}
}

func TestHTTPInvalidStatusPanicDoesNotBecomeOutcome(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	handler := embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(9999) }), slog.New(slog.NewJSONHandler(&out, nil)), embargo.NewScanner())
	func() {
		defer func() {
			if recover() == nil {
				t.Error("invalid status panic swallowed")
			}
		}()
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody))
	}()
	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["status"] != float64(0) {
		t.Fatalf("unwritten invalid status retained: %s", out.String())
	}
}

func TestHTTPRequestCanceledDuringMasking(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	detector := &cancelingScan{cancel: cancel}
	var out bytes.Buffer
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
	handler := embargo.NewHTTPHandler(next, slog.New(slog.NewJSONHandler(&out, nil)), embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(detector)))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(ctx, http.MethodGet, "/planted-target", http.NoBody))
	assertHTTPWithheld(t, out.Bytes(), canceledReason)
	if detector.calls != 1 {
		t.Fatal("scanned after request cancellation")
	}
}

func TestHTTPTargetPartsAndBounds(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, query, fragment, want, reason string
		force                               bool
	}{
		{name: "bare query", force: true, want: "/?"},
		{name: "flags", query: "public&flag=&x=a%20b", want: "/?public&flag=&x=a b"},
		{name: "fragment email", fragment: "alice@example.com", want: "/#[REDACTED]"},
		{name: "bad key escape", query: "%zz=planted", reason: maskingReason},
		{name: "bad value escape", query: "key=%zz", reason: maskingReason},
		{name: "oversized query", query: strings.Repeat("x", (1<<20)+1), reason: sizeReason},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
			req.URL.RawQuery, req.URL.Fragment, req.URL.ForceQuery = tc.query, tc.fragment, tc.force
			handler := embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }), slog.New(slog.NewJSONHandler(&out, nil)), embargo.NewScanner())
			handler.ServeHTTP(httptest.NewRecorder(), req)
			if tc.reason != "" {
				assertHTTPWithheld(t, out.Bytes(), tc.reason)
				return
			}
			var record map[string]any
			if err := json.Unmarshal(out.Bytes(), &record); err != nil || record["target"] != tc.want {
				t.Fatalf("record=%s error=%v want=%s", out.Bytes(), err, tc.want)
			}
		})
	}
}

type selectiveCancelDetector struct {
	cancel context.CancelFunc
	match  string
}

func (d selectiveCancelDetector) Scan(data []byte) []embargo.Finding {
	if string(data) == d.match {
		d.cancel()
	}
	return nil
}

func TestHTTPCancellationAtEveryInputBoundary(t *testing.T) {
	t.Parallel()
	for _, match := range []string{"key", "key: value", "fragment", "X-Public", "X-Public: value", "method: GET"} {
		t.Run(match, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/?key=value", http.NoBody)
			req.URL.Fragment = "fragment"
			req.Header.Set("X-Public", "value")
			var out bytes.Buffer
			scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(selectiveCancelDetector{cancel: cancel, match: match}))
			embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }), slog.New(slog.NewJSONHandler(&out, nil)), scanner).ServeHTTP(httptest.NewRecorder(), req)
			assertHTTPWithheld(t, out.Bytes(), canceledReason)
		})
	}
}

func TestHTTPHeaderSizeBoundaries(t *testing.T) {
	t.Parallel()
	for _, header := range []http.Header{
		{strings.Repeat("x", (1<<20)+1): {"value"}},
		{"X-Value": {strings.Repeat("x", (1<<20)+1)}},
		{"X-Value": {strings.Repeat("\x00", 1<<18)}},
	} {
		var out bytes.Buffer
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
		req.Header = header
		embargo.NewHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }), slog.New(slog.NewJSONHandler(&out, nil)), embargo.NewScanner()).ServeHTTP(httptest.NewRecorder(), req)
		assertHTTPWithheld(t, out.Bytes(), sizeReason)
	}
}
