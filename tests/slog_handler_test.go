package tests

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"reflect"
	"testing"

	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/nao1215/embargo"
	embargologrus "github.com/nao1215/embargo/adapters/logrus"
	embargozap "github.com/nao1215/embargo/adapters/zap"
	embargozerolog "github.com/nao1215/embargo/adapters/zerolog"
)

func TestLoggerKeyContextDifferential(t *testing.T) {
	const clientSecretKey = "client_secret"
	t.Parallel()
	for _, fixture := range []struct {
		value, want any
		key         string
	}{
		{731, referenceMarker, "cvv"},
		{"opaque-client-value", referenceMarker, clientSecretKey},
		{true, referenceMarker, clientSecretKey},
		{nil, referenceMarker, clientSecretKey},
		{12345678, referenceMarker, "bank account"},
		{"12/29", referenceMarker, "expiry"},
		{7, float64(7), metamorphicCountKey},
		{"retained", "retained", "status"},
		{true, true, "paid"},
	} {
		t.Run(fixture.key, func(t *testing.T) {
			t.Parallel()
			scanner := embargo.NewScanner()
			raw, err := json.Marshal(map[string]any{fixture.key: fixture.value})
			if err != nil {
				t.Fatal(err)
			}
			masked, err := scanner.MaskJSON(raw)
			if err != nil {
				t.Fatal(err)
			}
			expected := loggerField(t, masked, fixture.key)
			if !reflect.DeepEqual(expected, fixture.want) {
				t.Fatalf("MaskJSON got %v want %v", expected, fixture.want)
			}
			for _, name := range []string{"slog", "zap", "zerolog", "logrus"} {
				out := loggerOutput(t, scanner, name, fixture.key, fixture.value)
				if got := loggerField(t, out, fixture.key); !reflect.DeepEqual(got, expected) {
					t.Errorf("%s got %v want %v", name, got, expected)
				}
			}
		})
	}
}

func loggerField(t *testing.T, data []byte, key string) any {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	value, ok := fields[key]
	if !ok {
		t.Fatalf("missing %q in %s", key, data)
	}
	return value
}

func loggerOutput(t *testing.T, scanner *embargo.Scanner, name, key string, value any) []byte {
	t.Helper()
	var out bytes.Buffer
	switch name {
	case "slog":
		slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(&out, nil), scanner)).Info("event", key, value)
	case "zap":
		sink := embargozap.NewWriteSyncer(zapcore.AddSync(&out), scanner)
		logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zapcore.EncoderConfig{MessageKey: "msg"}), sink, zap.InfoLevel))
		logger.Info("event", zap.Any(key, value))
		if err := logger.Sync(); err != nil {
			t.Fatal(err)
		}
	case "zerolog":
		sink := embargozerolog.NewWriter(&out, scanner)
		logger := zerolog.New(sink)
		logger.Info().Interface(key, value).Msg("event")
		if err := sink.Close(); err != nil {
			t.Fatal(err)
		}
	case "logrus":
		logger := logrus.New()
		logger.SetOutput(&out)
		logger.SetFormatter(embargologrus.NewFormatter(&logrus.JSONFormatter{}, scanner))
		logger.WithField(key, value).Info("event")
	}
	return out.Bytes()
}
