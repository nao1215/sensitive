package embargo

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/nao1215/embargo/internal/saferecord"
)

// NewHTTPHandler writes one masked access record to logger after next handles each request.
// Authorization, Proxy-Authorization, Cookie and Set-Cookie values are always hidden,
// other header and query keys follow WithSensitiveKeys, and bodies are not logged;
// requests and responses pass through unchanged. All arguments are required.
// If masking fails, the record keeps only time, level, status, duration and a fixed
// reason. Attributes already bound to logger, as with logger.With, are written as
// they are; build logger from a handler without them. The [logging guide] covers
// contexts, panics and the failure record.
//
// [logging guide]: https://nao1215.github.io/embargo/getting-started/#bounds-and-failures
func NewHTTPHandler(next http.Handler, logger *slog.Logger, scanner *Scanner) http.Handler {
	if next == nil || nilHTTPHandler(next) || logger == nil || scanner == nil {
		panic("embargo: nil HTTP dependency")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writer := &httpLogWriter{ResponseWriter: w}
		start := saferecord.Now(r.Context())
		defer func() { logHTTPExchange(logger.Handler(), scanner, r, writer, start) }()
		next.ServeHTTP(writer, r)
		writer.completed = true
	})
}

func logHTTPExchange(next slog.Handler, scanner *Scanner, r *http.Request, w *httpLogWriter, start time.Time) {
	when := saferecord.Now(r.Context())
	duration := when.Sub(start)
	status := w.status
	if status == 0 && w.completed {
		status = http.StatusOK
	}
	ctx, cancel := saferecord.Budget(r.Context())
	defer cancel()
	const attributeCount = 6
	complete := false
	var cause error
	defer func() {
		_ = recover() //nolint:errcheck // Panic values may contain secrets.
		if !complete {
			// A downstream handler that also panics on the diagnostic must not
			// replace the response or the handler's own panic.
			defer func() { _ = recover() }() //nolint:errcheck // Same reason as above.
			if err := saferecord.Slog(ctx, next, when, slog.LevelInfo, attributeCount, saferecord.Reason(ctx, cause), slog.Int("status", status), slog.Duration("duration", duration)); err != nil {
				return
			}
		}
	}()
	if !next.Enabled(ctx, slog.LevelInfo) {
		complete = true
		return
	}
	scan := eventScanner{scanner: scanner, spare: nil, remaining: maxScanBytes}
	record, err := scan.httpRecord(ctx, r, w, when, duration, status)
	if err != nil {
		cause = err
		return
	}

	// All input-bearing values have been scanned once. Forward directly so a
	// shortened replacement cannot move public text into another detector's window.
	complete = true
	if err := next.Handle(ctx, record); err != nil {
		return
	}
}

func (scan *eventScanner) maskHTTPHeaders(ctx context.Context, header http.Header) (map[string]any, error) {
	if ctx.Err() != nil {
		return nil, saferecord.ErrCanceled
	}
	// Preflight before allocating JSON or scanning any potentially large field.
	if !headerWithinLimit(header) {
		return nil, saferecord.ErrSizeLimit
	}
	policy := fieldPolicy{scan: *scan, path: nil, prefix: "", prefixCrossed: false}
	defer func() { policy.release(); *scan = policy.scan }()
	safe := make(map[string]any, len(header))
	for key, values := range header {
		name, masked, err := headerField(ctx, &policy, key, values)
		if err != nil {
			return nil, err
		}
		safe[name] = masked
	}
	encoded, err := json.Marshal(safe)
	if err != nil {
		return nil, saferecord.ErrMasking
	}
	if len(encoded) > maxEventBytes {
		return nil, saferecord.ErrSizeLimit
	}
	return safe, nil
}

// headerField decides one header as a member: a sensitive or credential
// header is written as the marker and others mask each value.
func headerField(ctx context.Context, policy *fieldPolicy, key string, values []string) (name string, value any, err error) {
	decision, err := policy.member(ctx, key)
	if err != nil {
		return "", nil, err
	}
	policy.leave()
	if decision.sensitive || credentialHeader(key) {
		return decision.masked, redactionMarker, nil
	}
	masked, err := policy.scan.maskHeaderValues(ctx, key, values)
	return decision.masked, masked, err
}

// credentialHeader reports the standard headers that carry credentials.
func credentialHeader(key string) bool {
	return strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "Proxy-Authorization") || strings.EqualFold(key, "Cookie") || strings.EqualFold(key, "Set-Cookie")
}

// headerWithinLimit reports whether every header name and value together fit
// in one event, checked without overflow before any scan or allocation.
func headerWithinLimit(header http.Header) bool {
	size := 0
	for key, values := range header {
		if len(key) > maxEventBytes-size {
			return false
		}
		size += len(key)
		for _, value := range values {
			if len(value) > maxEventBytes-size {
				return false
			}
			size += len(value)
		}
	}
	return true
}

// maskHeaderValues masks one header's values in order. Location values are
// URLs whose credentials and query are masked by component; others are scalars.
func (scan *eventScanner) maskHeaderValues(ctx context.Context, key string, values []string) ([]string, error) {
	masked := make([]string, len(values))
	for i, value := range values {
		var err error
		if strings.EqualFold(key, "Location") {
			target, parseErr := url.Parse(value)
			if parseErr != nil {
				return nil, saferecord.ErrMasking
			}
			masked[i], err = scan.httpTarget(ctx, target)
		} else {
			masked[i], err = scan.maskScalar(ctx, value, key)
		}
		if err != nil {
			return nil, err
		}
	}
	return masked, nil
}

func (scan *eventScanner) httpTarget(ctx context.Context, target *url.URL) (string, error) {
	if ctx.Err() != nil {
		return "", saferecord.ErrCanceled
	}
	if len(target.RawQuery) > maxEventBytes {
		return "", saferecord.ErrSizeLimit
	}
	base := *target
	base.RawQuery, base.Fragment, base.RawFragment = "", "", ""
	base.ForceQuery = false
	if base.User != nil {
		base.User = url.User(redactionMarker)
	}
	prefix, err := scan.maskScalar(ctx, base.String(), "")
	if err != nil {
		return "", err
	}
	result := []byte(prefix)
	if target.RawQuery != "" || target.ForceQuery {
		query, queryErr := scan.httpQuery(ctx, target.RawQuery)
		if queryErr != nil {
			return "", queryErr
		}
		result = append(result, '?')
		result = append(result, query...)
	}
	if target.Fragment != "" {
		fragment, scanErr := scan.maskScalar(ctx, target.Fragment, "")
		if scanErr != nil {
			return "", scanErr
		}
		result = append(result, '#')
		result = append(result, fragment...)
	}
	return string(result), nil
}

func (scan *eventScanner) httpQuery(ctx context.Context, raw string) ([]byte, error) {
	policy := fieldPolicy{scan: *scan, path: nil, prefix: "", prefixCrossed: false}
	defer func() { policy.release(); *scan = policy.scan }()
	var result []byte
	for index, part := range strings.Split(raw, "&") {
		if index > 0 {
			result = append(result, '&')
		}
		key, value, hasValue, err := parseQueryPair(part)
		if err != nil {
			return nil, err
		}
		name, masked, err := policy.textMember(ctx, key, value)
		if err != nil {
			return nil, err
		}
		result = append(result, name...)
		if hasValue {
			result = append(append(result, '='), masked...)
		}
		if len(result) > maxEventBytes {
			return nil, saferecord.ErrSizeLimit
		}
	}
	return result, nil
}

// parseQueryPair splits one query parameter at its first equals sign and
// decodes both sides. A semicolon separator or a malformed escape withholds the
// whole query.
func parseQueryPair(part string) (key, value string, hasValue bool, err error) {
	if strings.Contains(part, ";") {
		return "", "", false, saferecord.ErrMasking
	}
	key, value, hasValue = strings.Cut(part, "=")
	key, err = url.QueryUnescape(key)
	if err != nil {
		return "", "", false, saferecord.ErrMasking
	}
	value, err = url.QueryUnescape(value)
	if err != nil {
		return "", "", false, saferecord.ErrMasking
	}
	return key, value, hasValue, nil
}

type httpLogWriter struct {
	http.ResponseWriter

	finalHeader http.Header
	status      int
	flushFailed bool
	completed   bool
}

// Unwrap exposes the original writer to http.ResponseController.
func (w *httpLogWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// WriteHeader snapshots the final response headers, leaving informational replies unretained.
func (w *httpLogWriter) WriteHeader(status int) {
	const largestHTTPStatus = 999
	if w.status == 0 && status <= largestHTTPStatus && (status >= http.StatusOK || status == http.StatusSwitchingProtocols) {
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

// httpRecord owns access-field sanitization; logHTTPExchange owns outcomes and recovery.
func (scan *eventScanner) httpRecord(ctx context.Context, r *http.Request, w *httpLogWriter, when time.Time, duration time.Duration, status int) (slog.Record, error) {
	defer scan.release()
	header := w.finalHeader
	if header == nil {
		header = w.Header()
	}
	target, err := scan.httpTarget(ctx, r.URL)
	if err != nil {
		return slog.Record{}, err
	}
	requestHeaders, err := scan.maskHTTPHeaders(ctx, r.Header)
	if err != nil {
		return slog.Record{}, err
	}
	responseHeaders, err := scan.maskHTTPHeaders(ctx, header)
	if err != nil {
		return slog.Record{}, err
	}
	method, err := scan.maskScalar(ctx, r.Method, "method")
	if err != nil {
		return slog.Record{}, err
	}
	record := slog.NewRecord(when, slog.LevelInfo, "http request", 0)
	record.AddAttrs(slog.String("method", method), slog.String("target", target), slog.Any("request_headers", requestHeaders), slog.Int("status", status), slog.Any("response_headers", responseHeaders), slog.Bool("flush_failed", w.flushFailed), slog.Bool("response_written", status != 0), slog.Duration("duration", duration))
	return record, nil
}
