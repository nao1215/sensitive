package embargo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"

	"github.com/nao1215/embargo"
)

func ExampleNewHTTPHandler() {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := embargo.NewHTTPHandler(next, logger, embargo.NewScanner())
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/profile?email=alice@example.com", http.NoBody)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var event struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(logs.Bytes(), &event); err != nil {
		panic(err)
	}
	fmt.Println(response.Code)
	fmt.Println(event.Target)
	// Output:
	// 204
	// /profile?email=%5BREDACTED%5D
}
