package embargozap_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/nao1215/embargo"
	embargozap "github.com/nao1215/embargo/adapters/zap"
)

type syncSink struct {
	bytes.Buffer

	syncs int
}

func (s *syncSink) Sync() error { s.syncs++; return io.ErrClosedPipe }

func TestSyncChecksCompletenessBeforeDelegating(t *testing.T) {
	t.Parallel()
	sink := &syncSink{}
	writer := embargozap.NewWriteSyncer(sink, embargo.NewScanner())
	if err := writer.Sync(); !errors.Is(err, io.ErrClosedPipe) || sink.syncs != 1 {
		t.Fatal("sync error lost")
	}
	if _, err := writer.Write([]byte(`{"partial":`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Sync(); err == nil || sink.syncs != 1 || sink.Len() != 0 {
		t.Fatal("partial record reached sink")
	}
}
