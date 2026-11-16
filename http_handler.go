package embargo

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/nao1215/embargo/internal/saferecord"
)

// NewHTTPHandler writes masked access records after next handles each request.
// Authorization, Cookie and Set-Cookie values are always hidden; other header and
// query keys follow WithSensitiveKeys. Redirect queries receive the same treatment.
// Request and response bytes passed to the service or client remain unchanged.
// Bodies are not logged. ResponseController, flushing, hijacking and HTTP/2 push
// delegate to the original writer; unsupported operations return ErrNotSupported.
// All three arguments are required. Access logging uses context.WithoutCancel
// with a 100 ms timeout, including for canceled requests. Masking failures emit a
// withheld record with time, level, a fixed reason and an attribute count. Running
// callbacks and sink I/O cannot be forcibly stopped. Fields introduced downstream
// require their own masking boundary; sink failures cannot change the response.
func NewHTTPHandler(next http.Handler, logger *slog.Logger, scanner *Scanner) http.Handler {
	if next == nil || nilHTTPHandler(next) || logger == nil || scanner == nil {
		panic("embargo: nil HTTP dependency")
	}
	safeHandler := NewSlogHandler(logger.Handler(), scanner)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writer := &httpLogWriter{ResponseWriter: w}
		defer logHTTPExchange(logger.Handler(), safeHandler, scanner, r, writer)
		next.ServeHTTP(writer, r)
	})
}

func logHTTPExchange(next, safe slog.Handler, scanner *Scanner, r *http.Request, w *httpLogWriter) {
	ctx, cancel := saferecord.Budget(r.Context())
	defer cancel()
	const attributeCount = 6
	when := time.Now()
	complete := false
	var cause error
	defer func() {
		_ = recover() //nolint:errcheck // Panic values may contain secrets.
		if !complete {
			if err := saferecord.Slog(ctx, next, when, slog.LevelInfo, attributeCount, saferecord.Reason(ctx, cause)); err != nil {
				return
			}
		}
	}()
	if !safe.Enabled(ctx, slog.LevelInfo) {
		complete = true
		return
	}
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	header := w.finalHeader
	if header == nil {
		header = w.Header()
	}
	target, err := scanner.httpTarget(ctx, r.URL)
	if err != nil {
		cause = err
		return
	}
	requestHeaders, err := scanner.maskHTTPHeaders(ctx, r.Header)
	if err != nil {
		cause = err
		return
	}
	responseHeaders, err := scanner.maskHTTPHeaders(ctx, header)
	if err != nil {
		cause = err
		return
	}
	record := slog.NewRecord(when, slog.LevelInfo, "http request", 0)
	record.AddAttrs(slog.String("method", r.Method), slog.String("target", target), slog.Any("request_headers", requestHeaders), slog.Int("status", status), slog.Any("response_headers", responseHeaders), slog.Bool("flush_failed", w.flushFailed))
	complete = true
	if err := safe.Handle(ctx, record); err != nil {
		return
	}
}

func (s *Scanner) maskHTTPHeaders(ctx context.Context, header http.Header) (http.Header, error) {
	if ctx.Err() != nil {
		return nil, saferecord.ErrCanceled
	}
	safe := header.Clone()
	for key, values := range safe {
		if ctx.Err() != nil {
			return nil, saferecord.ErrCanceled
		}
		if strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "Cookie") || strings.EqualFold(key, "Set-Cookie") || s.sensitiveKey(key) {
			safe[key] = []string{redactionMarker}
			continue
		}
		if strings.EqualFold(key, "Location") {
			for i, value := range values {
				target, err := url.Parse(value)
				if err != nil {
					return nil, saferecord.ErrMasking
				}
				masked, scanErr := s.httpTarget(ctx, target)
				if scanErr != nil {
					return nil, scanErr
				}
				values[i] = masked
			}
		}
	}
	return safe, nil
}

func (s *Scanner) httpTarget(ctx context.Context, target *url.URL) (string, error) {
	if ctx.Err() != nil {
		return "", saferecord.ErrCanceled
	}
	copyURL := *target
	if copyURL.User != nil {
		copyURL.User = url.User(redactionMarker)
	}
	query, err := url.ParseQuery(copyURL.RawQuery)
	if err != nil {
		return "", saferecord.ErrMasking
	}
	scan := eventScanner{scanner: s, remaining: maxScanBytes}
	for key, values := range query {
		if ctx.Err() != nil {
			return "", saferecord.ErrCanceled
		}
		for i, value := range values {
			if s.sensitiveKey(key) {
				values[i] = redactionMarker
			} else {
				masked, scanErr := scan.maskScalar(ctx, value, key)
				if scanErr != nil {
					return "", scanErr
				}
				values[i] = masked
			}
		}
	}
	copyURL.RawQuery = query.Encode()
	masked, err := scan.maskScalar(ctx, copyURL.String(), "")
	if err != nil {
		return "", err
	}
	return masked, nil
}

type httpLogWriter struct {
	http.ResponseWriter

	finalHeader http.Header
	status      int
	flushFailed bool
}

// Unwrap exposes the original writer to http.ResponseController.
func (w *httpLogWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// WriteHeader snapshots the final response headers, leaving informational replies unretained.
func (w *httpLogWriter) WriteHeader(status int) {
	if w.status == 0 && (status >= 200 || status == http.StatusSwitchingProtocols) {
		w.status = status
		w.finalHeader = w.Header().Clone()
	}
	w.ResponseWriter.WriteHeader(status)
}

// Write records an implicit 200 before forwarding the body unchanged.
func (w *httpLogWriter) Write(data []byte) (int, error) {
	if w.status != 0 {
		return w.ResponseWriter.Write(data)
	}
	w.status = http.StatusOK
	n, err := w.ResponseWriter.Write(data)
	w.finalHeader = w.Header().Clone()
	return n, err
}

// FlushError sends pending headers and returns the underlying flush result.
func (w *httpLogWriter) FlushError() error {
	if err := http.NewResponseController(w.ResponseWriter).Flush(); err != nil {
		return err
	}
	if w.status == 0 {
		w.status = http.StatusOK
		w.finalHeader = w.Header().Clone()
	}
	return nil
}

// Flush retains a failed flush as a boolean in the access record.
func (w *httpLogWriter) Flush() {
	if err := w.FlushError(); err != nil {
		w.flushFailed = true
	}
}

// Hijack transfers the original connection through ResponseController.
func (w *httpLogWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

// Push delegates HTTP/2 promises when the writer supports them.
func (w *httpLogWriter) Push(target string, options *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, options)
	}
	return http.ErrNotSupported
}

func nilHTTPHandler(next http.Handler) bool {
	value := reflect.ValueOf(next)
	switch value.Kind() { //nolint:exhaustive // Only these implementation kinds can hold nil.
	case reflect.Pointer, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan, reflect.Interface:
		return value.IsNil()
	default:
		return false
	}
}
