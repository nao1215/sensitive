package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"

	"pgregory.net/rapid"

	"github.com/nao1215/embargo/embargotest"
)

func TestHTTPStateProperties(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		operations := rapid.SliceOfN(rapid.IntRange(0, 4), 0, 30).Draw(rt, "operations")
		probe := &observationTB{TB: t}
		r := embargotest.New(probe)
		actual := r.HTTP("http")
		expected := httptest.NewRecorder()
		for _, op := range operations {
			for _, writer := range []http.ResponseWriter{actual, expected} {
				switch op {
				case 0:
					writer.Header().Set("X-State", "changed")
				case 1:
					if _, err := writer.Write([]byte("data")); err != nil {
						rt.Fatal("write failed")
					}
				case 2:
					writer.WriteHeader(http.StatusCreated)
				case 3:
					f, ok := writer.(http.Flusher)
					if !ok {
						rt.Fatal("flusher missing")
					}
					f.Flush()
				case 4:
					writer.Header().Set("X-Other", "value")
				}
			}
		}
		result := expected.Result()
		if err := result.Body.Close(); err != nil {
			rt.Fatal("close failed")
		}
		r.Expect("http/body", func(data []byte) bool { return bytes.Equal(data, expected.Body.Bytes()) })
		r.Expect("http/status", func(data []byte) bool { return string(data) == strconv.Itoa(result.StatusCode) })
		r.Expect("http/headers", func(data []byte) bool {
			var h http.Header
			return json.Unmarshal(data, &h) == nil && reflect.DeepEqual(h, result.Header)
		})
		if !r.Check() {
			rt.Fatal("HTTP state model disagrees")
		}
		probe.finish()
	})
}
