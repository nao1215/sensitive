package embargo

import (
	"bufio"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
)

// NewHTTPHandler writes masked access records after next handles each request.
// Authorization, Cookie and Set-Cookie values are always hidden; other header and
// query keys follow WithSensitiveKeys. Redirect queries receive the same treatment.
// Request and response bytes passed to the service or client remain unchanged.
// Bodies are not logged. ResponseController, flushing, hijacking and HTTP/2 push
// delegate to the original writer; unsupported operations return ErrNotSupported.
// All three arguments are required. Logging failures drop the record, and fields
// introduced by the downstream logger require its own masking boundary.
func NewHTTPHandler(next http.Handler, logger *slog.Logger, scanner *Scanner) http.Handler {
	if next == nil || nilHTTPHandler(next) || logger == nil || scanner == nil {
		panic("embargo: nil HTTP dependency")
	}
	safeLogger := slog.New(NewSlogHandler(logger.Handler(), scanner))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writer := &httpLogWriter{ResponseWriter: w}
		defer logHTTPExchange(safeLogger, scanner, r, writer)
		next.ServeHTTP(writer, r)
	})
}

func logHTTPExchange(logger *slog.Logger, scanner *Scanner, r *http.Request, w *httpLogWriter) {
	// A broken custom detector must not turn an access-log failure into a service failure.
	defer func() {
		_ = recover() //nolint:errcheck // Suppress panic values at the logging boundary.
	}()
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	header := w.finalHeader
	if header == nil {
		header = w.Header()
	}
	logger.LogAttrs(r.Context(), slog.LevelInfo, "http request",
		slog.String("method", r.Method), slog.String("target", scanner.httpTarget(r.URL)),
		slog.Any("request_headers", scanner.maskHTTPHeaders(r.Header)), slog.Int("status", status),
		slog.Any("response_headers", scanner.maskHTTPHeaders(header)), slog.Bool("flush_failed", w.flushFailed))
}

func (s *Scanner) maskHTTPHeaders(header http.Header) http.Header {
	safe := header.Clone()
	for key, values := range safe {
		if strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "Cookie") || strings.EqualFold(key, "Set-Cookie") || s.sensitiveKey(key) {
			safe[key] = []string{redactionMarker}
		} else if strings.EqualFold(key, "Location") {
			for i, value := range values {
				target, err := url.Parse(value)
				if err != nil {
					values[i] = redactionMarker
				} else {
					values[i] = s.httpTarget(target)
				}
			}
		}
	}
	return safe
}

func (s *Scanner) httpTarget(target *url.URL) string {
	copyURL := *target
	if copyURL.User != nil {
		copyURL.User = url.User(redactionMarker)
	}
	query, err := url.ParseQuery(copyURL.RawQuery)
	if err != nil {
		return redactionMarker
	}
	scan := eventScanner{scanner: s, remaining: maxScanBytes}
	for key, values := range query {
		for i, value := range values {
			if s.sensitiveKey(key) {
				values[i] = redactionMarker
			} else {
				masked, scanErr := scan.maskScalar(value, key)
				if scanErr != nil {
					return redactionMarker
				}
				values[i] = masked
			}
		}
	}
	copyURL.RawQuery = query.Encode()
	return Mask(copyURL.String(), s.ScanString(copyURL.String()))
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
