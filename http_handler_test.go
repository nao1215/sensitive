package embargo_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nao1215/embargo"
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
	if strings.Contains(logs.String(), "opaque") || !strings.Contains(logs.String(), `"status":200`) {
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
	if response.Code != http.StatusNoContent || logs.Len() != 0 {
		t.Fatal("logging failure reached service or output")
	}
}

type controlWriter struct {
	header   http.Header
	deadline bool
	pushed   bool
}

func (w *controlWriter) Header() http.Header                  { return w.header }
func (*controlWriter) WriteHeader(int)                        {}
func (*controlWriter) Write(p []byte) (int, error)            { return len(p), nil }
func (w *controlWriter) SetWriteDeadline(time.Time) error     { w.deadline = true; return nil }
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
			detector := &cancelingScan{cancel: cancel}
			scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithDetector(detector))
			var out bytes.Buffer
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
			handler := embargo.NewHTTPHandler(next, slog.New(slog.NewJSONHandler(&out, nil)), scanner)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequestWithContext(ctx, http.MethodGet, "/pay?first=public&second=public", http.NoBody))
			want := 1
			if alreadyCanceled {
				want = 0
			}
			if response.Code != http.StatusAccepted || out.Len() != 0 || detector.calls != want {
				t.Fatalf("status=%d bytes=%d scans=%d want=%d", response.Code, out.Len(), detector.calls, want)
			}
		})
	}
}
