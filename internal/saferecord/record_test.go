package saferecord

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"
)

func TestDiagnosticsContainOnlyFixedData(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		reason  string
		failure SanitizationError
	}{{"masking error", ErrMasking}, {"size limit", ErrSizeLimit}, {"canceled", ErrCanceled}} {
		if Message(tc.failure) != "embargo: record withheld ("+tc.reason+")" {
			t.Fatal("wrong reason")
		}
		if Reason(t.Context(), tc.failure) != tc.failure || tc.failure.Error() != "embargo: invalid or unmaskable JSON" {
			t.Fatal("classification changed")
		}
		var sink bytes.Buffer
		if err := Slog(t.Context(), slog.NewJSONHandler(&sink, nil), time.Unix(7, 0).UTC(), slog.LevelWarn, 3, tc.failure); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(sink.Bytes(), []byte(Message(tc.failure))) {
			t.Fatal("missing diagnostic")
		}
		for _, level := range []string{"warning", "planted-level"} {
			raw := JSON(time.Unix(7, 0).UTC(), level, 3, tc.failure)
			if !json.Valid(raw) || bytes.Contains(raw, []byte("planted")) {
				t.Fatal("unsafe JSON")
			}
		}
	}
	if Reason(t.Context(), errors.New("planted-error")) != ErrMasking {
		t.Fatal("untrusted error affected reason")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if Reason(ctx, ErrSizeLimit) != ErrCanceled {
		t.Fatal("cancellation must win")
	}
	detached, stop := Budget(ctx)
	defer stop()
	if _, ok := detached.Deadline(); !ok || detached.Err() != nil {
		t.Fatal("missing detached budget")
	}
}
