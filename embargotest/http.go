package embargotest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

type response struct {
	recorder                        *Recorder
	body, headers, trailers, status *stream
	interim                         *stream
	header                          http.Header
	trailerNames                    []string
	code                            int
	finalized                       bool
}

// HTTP returns a recorder for one handler's status, headers, body and trailers.
// Expectations use name/status, name/headers, name/body and name/trailers.
// Stop the handler before Check; see the package HTTP section for representation
// and concurrency rules.
func (r *Recorder) HTTP(name string) http.ResponseWriter {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, suffix := range []string{"/body", "/headers", "/trailers", "/status"} {
		if _, exists := r.sinks[name+suffix]; exists {
			r.failed = true
		}
	}
	w := &response{interim: &stream{recorder: r}, recorder: r, header: make(http.Header), body: r.writer(name + "/body"), headers: r.writer(name + "/headers"), trailers: r.writer(name + "/trailers"), status: r.writer(name + "/status")}
	if name == "" || len(name) > maxNameBytes-len("/trailers") || len(r.responses) >= maxSinks/4 {
		r.failed = true
		return w
	}
	r.responses = append(r.responses, w)
	return w
}

// Header exposes the response header map used by the HTTP writer contract.
func (w *response) Header() http.Header { return w.header }

// WriteHeader observes interim headers and commits the final response status.
func (w *response) WriteHeader(code int) {
	w.recorder.mu.Lock()
	defer w.recorder.mu.Unlock()
	if w.recorder.checked {
		w.recorder.failed = true
		return
	}
	if code < 100 || code > 999 {
		panic("embargotest: invalid HTTP status")
	}
	if w.code != 0 {
		return
	}
	if code >= 100 && code < 200 && code != 101 {
		// An informational response sends the current headers too, so scan
		// them for the canary even though they are not the final headers.
		snapshot := w.snapshot(w.header, func(key string) bool { return !strings.HasPrefix(key, http.TrailerPrefix) })
		w.recordHeaders(w.interim, snapshot)
		return
	}
	w.commit(code)
}

func (w *response) commit(code int) {
	w.code = code
	snapshot := w.snapshot(w.header, func(key string) bool { return !strings.HasPrefix(key, http.TrailerPrefix) })
	for _, value := range snapshot.Values("Trailer") {
		for name := range strings.SplitSeq(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				w.trailerNames = append(w.trailerNames, http.CanonicalHeaderKey(name))
			}
		}
	}
	w.recordHeaders(w.headers, snapshot)
}

// Write captures body bytes under the shared output limit.
func (w *response) Write(data []byte) (int, error) {
	r := w.recorder
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.checked {
		r.failed = true
		return len(data), nil
	}
	if w.code == 0 {
		if w.header.Get("Content-Type") == "" && w.header.Get("Transfer-Encoding") == "" {
			sniff := data
			//nolint:mnd // This bound follows HTTP sniffing, JSON nesting, metadata encoding, or child-name limits.
			if len(sniff) > 512 {
				sniff = sniff[:512]
			}
			w.header.Set("Content-Type", http.DetectContentType(sniff))
		}
		w.commit(http.StatusOK)
	}
	return r.capture(w.body, data)
}

// Flush records an implicit successful status before flushing the response.
func (w *response) Flush() { w.WriteHeader(http.StatusOK) }

func (w *response) finalize() {
	if w.finalized {
		return
	}
	w.finalized = true
	if w.code == 0 {
		w.commit(http.StatusOK)
	}
	w.recordHeaders(w.trailers, w.trailerSnapshot())
	if _, err := w.recorder.capture(w.status, []byte(strconv.Itoa(w.code))); err != nil {
		w.recorder.failed = true
	}
}

// trailersChanged reports whether the trailers in the Header map differ from
// those recorded when the response was finalized. The caller holds mu.
func (w *response) trailersChanged() bool {
	if !w.finalized {
		return false
	}
	//nolint:errchkjson // Keep marshal errors explicit under errcheck if serialized types evolve.
	encoded, err := json.Marshal(w.trailerSnapshot())
	return err != nil || !bytes.Equal(encoded, w.trailers.data)
}

func (w *response) trailerSnapshot() http.Header {
	trailers := w.snapshot(w.header, func(key string) bool {
		if strings.HasPrefix(key, http.TrailerPrefix) {
			return true
		}
		for _, name := range w.trailerNames {
			if strings.EqualFold(key, name) {
				return true
			}
		}
		return false
	})
	normalized := make(http.Header)
	for key, values := range trailers {
		key = strings.TrimPrefix(key, http.TrailerPrefix)
		normalized[key] = values
	}
	return normalized
}

func (w *response) snapshot(header http.Header, include func(string) bool) http.Header {
	r := w.recorder
	snapshot := make(http.Header)
	budget := r.maxBytes - r.retained
	for key, values := range header {
		if !include(key) {
			continue
		}
		//nolint:mnd // This bound follows HTTP sniffing, JSON nesting, metadata encoding, or child-name limits.
		budget -= int64(len(key)) + 8
		if budget < 0 {
			r.failed = true
			return snapshot
		}
		r.observeMetadata([]byte(key))
		snapshot[key] = nil
		for _, value := range values {
			//nolint:mnd // This bound follows HTTP sniffing, JSON nesting, metadata encoding, or child-name limits.
			budget -= int64(len(value)) + 4
			if budget < 0 {
				r.failed = true
				return snapshot
			}
			r.observeMetadata([]byte(value))
			snapshot[key] = append(snapshot[key], value)
		}
	}
	return snapshot
}

func (w *response) recordHeaders(target *stream, header http.Header) {
	//nolint:errchkjson // Keep marshal errors explicit under errcheck if serialized types evolve.
	encoded, err := json.Marshal(header)
	if err != nil {
		w.recorder.failed = true
		return
	}
	if _, err := w.recorder.capture(target, encoded); err != nil {
		w.recorder.failed = true
	}
}
