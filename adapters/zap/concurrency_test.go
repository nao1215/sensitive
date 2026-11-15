package embargozap_test

import (
	"sync"
	"testing"

	"github.com/nao1215/embargo"
	embargozap "github.com/nao1215/embargo/adapters/zap"
)

type sharedSink struct{ calls int }

func (s *sharedSink) Write(data []byte) (int, error) { s.calls++; return len(data), nil }
func (s *sharedSink) Sync() error                    { s.calls++; return nil }

func TestWriteAndSyncSerializeTheSink(t *testing.T) {
	t.Parallel()
	sink := &sharedSink{}
	writer := embargozap.NewWriteSyncer(sink, embargo.NewScanner(embargo.WithKinds()))
	var group sync.WaitGroup
	for range 20 {
		group.Go(func() {
			for range 20 {
				if _, err := writer.Write([]byte("{\"event\":\"accepted\"}\n")); err != nil {
					t.Error(err)
				}
				if err := writer.Sync(); err != nil {
					t.Error(err)
				}
			}
		})
	}
	group.Wait()
	if sink.calls != 800 {
		t.Fatal("sink calls were lost")
	}
}
