package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nao1215/embargo/embargotest"
)

func TestHTTPRedirectAndErrorLeakPaths(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{scenarioRedirect, scenarioErrorKey, "clean-response"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			probe := &observationTB{TB: t}
			r := embargotest.New(probe)
			w := r.HTTP("response")
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
			switch mode {
			case scenarioRedirect:
				http.Redirect(w, req, "/login?token="+string(r.Canary()), http.StatusFound)
			case scenarioErrorKey:
				http.Error(w, string(r.Canary()), http.StatusInternalServerError)
			default:
				http.Error(w, "request failed", http.StatusInternalServerError)
			}
			r.Expect("response/body", func(data []byte) bool { return len(data) > 0 })
			if r.Check() != (mode == "clean-response") {
				t.Fatal("wrong HTTP verdict")
			}
			probe.finish()
		})
	}
}
