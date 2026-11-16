package saferecord

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
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
		if Reason(t.Context(), tc.failure) != tc.failure || !strings.HasPrefix(tc.failure.Error(), "embargo: ") {
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

func TestAccessBudgetUsesOriginalContextUntilCanceled(t *testing.T) {
	t.Parallel()
	calls := 0
	when := time.Unix(7, 0)
	ctx := WithAccessPolicy(t.Context(), AccessPolicy{Now: func() time.Time { return when }, Timeout: func(parent context.Context, limit time.Duration) (context.Context, context.CancelFunc) {
		calls++
		if limit != 100*time.Millisecond || parent.Err() != nil {
			t.Fatal("wrong detached budget")
		}
		return context.WithCancel(parent)
	}})
	original, stop := Budget(ctx)
	stop()
	if original != ctx || calls != 0 || Now(ctx) != when {
		t.Fatal("ordinary context was detached or clock was ignored")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	detached, stop := Budget(canceled)
	defer stop()
	if calls != 1 || detached.Err() != nil || Now(detached) != when {
		t.Fatal("canceled context lost its internal policy")
	}
}

func TestUnknownReasonUsesFixedMaskingMessage(t *testing.T) {
	t.Parallel()
	if SanitizationError(255).Error() != ErrMasking.Error() {
		t.Fatal("unknown error did not use fixed fallback")
	}
	if Message(SanitizationError(255)) != "embargo: record withheld (masking error)" {
		t.Fatal("unknown reason exposed an unstable diagnostic")
	}
}
