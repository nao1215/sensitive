package embargotest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestHTTPDifferential(t *testing.T) {
	t.Parallel()
	scenarios := []func(http.ResponseWriter){
		func(w http.ResponseWriter) {
			w.Header().Set("X-Result", "before")
			w.WriteHeader(http.StatusOK)
			w.Header().Set("X-Result", "after")
		},
		func(w http.ResponseWriter) {
			if _, err := w.Write(nil); err != nil {
				t.Fatal(err)
			}
		},
		func(w http.ResponseWriter) {
			w.Header().Set("X-Result", "accepted")
			if _, err := w.Write([]byte("ok")); err != nil {
				t.Fatal(err)
			}
		},
		func(w http.ResponseWriter) {
			w.Header().Set("Trailer", "X-Final")
			w.WriteHeader(http.StatusAccepted)
			if _, err := w.Write([]byte("ok")); err != nil {
				t.Fatal(err)
			}
			w.Header().Set("X-Final", "complete")
			w.Header().Set("X-Late", "not sent")
		},
		func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusCreated)
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set(http.TrailerPrefix+"X-End", "done")
		},
		func(w http.ResponseWriter) {
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Fatal("no flusher")
			}
			flusher.Flush()
		},
		func(http.ResponseWriter) {},
	}
	for _, handler := range scenarios {
		oracle := httptest.NewRecorder()
		handler(oracle)
		result := oracle.Result()
		if err := result.Body.Close(); err != nil {
			t.Fatal(err)
		}
		r := New(t)
		w := r.HTTP("http")
		handler(w)
		r.Expect("http/body", func(data []byte) bool { return string(data) == oracle.Body.String() })
		r.Expect("http/status", func(data []byte) bool { return string(data) == strconv.Itoa(result.StatusCode) })
		r.Expect("http/headers", func(data []byte) bool {
			var h http.Header
			return json.Unmarshal(data, &h) == nil && reflect.DeepEqual(h, result.Header)
		})
		r.Expect("http/trailers", func(data []byte) bool {
			var h http.Header
			return json.Unmarshal(data, &h) == nil && (len(h) == 0 && len(result.Trailer) == 0 || reflect.DeepEqual(h, result.Trailer))
		})
		if _, ok := w.(http.Hijacker); ok {
			t.Fatal("hijacker fabricated")
		}
		if _, ok := w.(http.Pusher); ok {
			t.Fatal("pusher fabricated")
		}
		r.Check()
	}
}

func TestHTTPLeaksAndLimits(t *testing.T) {
	t.Parallel()
	//nolint:goconst // Independent scenarios keep their fixture and expected error literals local.
	for _, where := range []string{"body", "header-value", "header-name", "trailer", "huge-header", "huge-body"} {
		t.Run(where, func(t *testing.T) {
			t.Parallel()
			p := &probeTB{TB: t}
			r := New(p, WithLimits(256, defaultTimeout))
			w := r.HTTP("http")
			canary := string(r.Canary())
			switch where {
			case "body":
				if _, err := fmt.Fprint(w, canary); err != nil {
					t.Fatal(err)
				}
			case "header-value":
				w.Header().Set("X-Token", canary)
			case "header-name":
				w.Header()[canary] = []string{"value"}
			case "trailer":
				w.Header().Set("Trailer", "X-End")
				w.WriteHeader(http.StatusOK)
				w.Header().Set("X-End", canary)
			case "huge-header":
				w.Header().Set("X-Huge", string(make([]byte, 300)))
			case "huge-body":
				if _, err := w.Write(make([]byte, 300)); err != nil {
					t.Fatal(err)
				}
			}
			r.Expect("http/status", func([]byte) bool { return true })
			if r.Check() {
				t.Fatal("invalid HTTP capture passed")
			}
			p.finish()
		})
	}
}

func TestHTTPStatusAndLifecycle(t *testing.T) {
	t.Parallel()
	r := New(t)
	w := r.HTTP("http")
	w.WriteHeader(http.StatusContinue)
	w.WriteHeader(http.StatusEarlyHints)
	w.WriteHeader(http.StatusOK)
	r.Expect("http/status", func(b []byte) bool { return string(b) == "200" })
	r.Check()
	for _, code := range []int{101, 999} {
		r := New(t)
		w := r.HTTP("http")
		w.WriteHeader(code)
		r.Expect("http/status", func(b []byte) bool { return string(b) == strconv.Itoa(code) })
		r.Check()
	}
	for _, code := range []int{99, 1000} {
		p := &probeTB{TB: t}
		r := New(p)
		w := r.HTTP("http")
		func() {
			defer func() {
				if recover() == nil {
					t.Error("invalid status did not panic")
				}
			}()
			w.WriteHeader(code)
		}()
		r.Expect("http/status", func(b []byte) bool { return string(b) == "200" })
		r.Check()
		p.finish()
	}
	for _, mode := range []string{"header", "body"} {
		p := &probeTB{TB: t}
		r := New(p)
		w := r.HTTP("http")
		r.Expect("http/status", func([]byte) bool { return true })
		r.Check()
		if mode == "header" {
			w.WriteHeader(http.StatusOK)
		} else {
			if _, err := w.Write([]byte("late")); err != nil {
				t.Fatal(err)
			}
		}
		p.finish()
		if p.errors == 0 {
			t.Fatal("late HTTP write was not detected")
		}
	}
}

func TestHTTPNameBoundary(t *testing.T) {
	t.Parallel()
	r := New(t)
	name := strings.Repeat("a", 119)
	r.HTTP(name)
	r.Expect(name+"/status", func(b []byte) bool { return string(b) == "200" })
	r.Check()
	for _, name := range []string{"", strings.Repeat("a", 120)} {
		p := &probeTB{TB: t}
		r := New(p)
		r.HTTP(name)
		r.Expect(name+"/body", func([]byte) bool { return true })
		if r.Check() {
			t.Fatal("invalid HTTP name accepted")
		}
		p.finish()
	}
	p := &probeTB{TB: t}
	failed := New(p)
	failed.HTTP("reused")
	failed.HTTP("reused")
	failed.Expect("reused/status", func([]byte) bool { return true })
	if failed.Check() {
		t.Fatal("reused response accepted")
	}
	p.finish()
}

func TestHTTPMetadataBudget(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"remaining", "empty-values", "many-keys"} {
		p := &probeTB{TB: t}
		r := New(p, WithLimits(64, defaultTimeout))
		w, ok := r.HTTP("http").(*response)
		if !ok {
			t.Fatal("response fixture type")
		}
		headers := make(http.Header)
		switch mode {
		case "remaining":
			write(t, r, "prefix", make([]byte, 48))
			for i := range 100 {
				headers[strconv.Itoa(i)] = []string{"value"}
			}
		case "empty-values":
			headers["X"] = make([]string, 10000)
		case "many-keys":
			for i := range 10000 {
				headers[strconv.Itoa(i)] = nil
			}
		}
		budget := r.maxBytes - r.retained
		r.mu.Lock()
		snapshot := w.snapshot(headers, func(string) bool { return true })
		r.mu.Unlock()
		// Every retained key, value and value element needs space in the capture.
		// Check a coarse resource bound, independently of JSON overhead estimates.
		size := int64(len(snapshot))
		for key, values := range snapshot {
			size += int64(len(key) + len(values))
			for _, value := range values {
				size += int64(len(value))
			}
		}
		if size > budget {
			t.Fatal("metadata snapshot exceeded remaining capture budget")
		}
		r.Expect("http/status", func([]byte) bool { return true })
		if r.Check() {
			t.Fatal("oversized metadata did not fail")
		}
		p.finish()
	}
}

func TestHTTPInformationalHeadersAreScanned(t *testing.T) {
	t.Parallel()
	for _, code := range []int{http.StatusContinue, http.StatusEarlyHints} {
		p := &probeTB{TB: t}
		r := New(p)
		w := r.HTTP("http")
		w.Header().Set("X-Token", string(r.Canary()))
		w.WriteHeader(code)
		w.Header().Del("X-Token")
		if _, err := fmt.Fprint(w, "ok"); err != nil {
			panic(err)
		}
		r.Expect("http/body", func(b []byte) bool { return string(b) == "ok" })
		if r.Check() {
			t.Fatalf("canary in a %d response accepted", code)
		}
		p.finish()
		//nolint:goconst // Independent scenarios keep their fixture and expected error literals local.
		if len(p.messages) != 1 || p.messages[0] != "embargotest: the fake secret appeared in captured output" {
			t.Fatalf("messages = %q", p.messages)
		}
	}
}

func TestHTTPFinalHeaderLeakNamesTheSecret(t *testing.T) {
	t.Parallel()
	p := &probeTB{TB: t}
	r := New(p)
	w := r.HTTP("http")
	w.Header().Set("X-Token", string(r.Canary()))
	w.WriteHeader(http.StatusOK)
	r.Expect("http/status", func(b []byte) bool { return string(b) == "200" })
	if r.Check() {
		t.Fatal("header canary accepted")
	}
	p.finish()
	if len(p.messages) != 1 || p.messages[0] != "embargotest: the fake secret appeared in captured output" {
		t.Fatalf("messages = %q", p.messages)
	}
}

func TestHTTPTrailerChangeAfterCheckIsReported(t *testing.T) {
	t.Parallel()
	p := &probeTB{TB: t}
	r := New(p)
	w := r.HTTP("http")
	w.Header().Set("Trailer", "X-Final")
	w.WriteHeader(http.StatusOK)
	w.Header().Set("X-Final", "ok")
	r.Expect("http/status", func(b []byte) bool { return string(b) == "200" })
	if !r.Check() {
		t.Fatal("complete response rejected")
	}
	w.Header().Set("X-Final", string(r.Canary()))
	p.finish()
	if len(p.messages) != 1 || p.messages[0] != "embargotest: output or registration changed after Check" {
		t.Fatalf("messages = %q", p.messages)
	}
}

func TestHTTPRepeatedCheckAndLateTrailers(t *testing.T) {
	t.Parallel()
	p := &probeTB{TB: t}
	r := New(p)
	response := r.HTTP("http")
	response.Header().Set("Trailer", "X-Result")
	data := bytes.Repeat([]byte("a"), 600)
	if n, err := response.Write(data); n != len(data) || err != nil {
		t.Fatal("body capture failed")
	}
	response.Header().Set("X-Result", "ok")
	r.Expect("http/body", func(got []byte) bool { return bytes.Equal(got, data) })
	r.Expect("http/headers", func(got []byte) bool { return bytes.Contains(got, []byte("text/plain; charset=utf-8")) })
	for range 2 {
		if !r.Check() {
			t.Fatal("completed response did not stay valid")
		}
	}
	response.Header().Set("X-Result", "changed")
	if r.Check() || p.errors == 0 {
		t.Fatal("changed trailer accepted")
	}
	p.finish()
}
