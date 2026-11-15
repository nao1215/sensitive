package embargozap_test

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/nao1215/embargo"
	embargozap "github.com/nao1215/embargo/adapters/zap"
	"github.com/nao1215/embargo/embargotest"
)

type objectCanary struct{ value string }

func (o objectCanary) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("token", o.value)
	enc.AddString("email", "alice@example.com")
	return nil
}

type arrayCanary struct{ value string }

func (a arrayCanary) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	enc.AppendString(a.value)
	return enc.AppendObject(objectCanary(a))
}

//nolint:goconst // Keep field names and expected bytes visible beside the real logger calls.
func TestObjectArrayInlineAndReflectedFields(t *testing.T) {
	t.Parallel()
	canary := "public-marshaler-canary"
	scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail), embargo.WithDetector(literal{value: []byte(canary)}))
	r := embargotest.New(t, embargotest.WithCanary([]byte(canary)), embargotest.WithScanner(scanner))
	writer := embargozap.NewWriteSyncer(zapcore.AddSync(r.Writer("out")), scanner)
	logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zapcore.EncoderConfig{MessageKey: "msg", NameKey: "name"}), writer, zap.InfoLevel))
	logger.With(zap.Object("pre", objectCanary{value: canary})).Named(canary).Info("event", zap.Object("object", objectCanary{value: canary}), zap.Array("array", arrayCanary{value: canary}), zap.Inline(objectCanary{value: canary}), zap.Reflect("reflected", map[string]string{"token": canary}))
	if err := logger.Sync(); err != nil {
		t.Fatal(err)
	}
	r.ExpectJSON("out", []string{"object"}, map[string]string{"token": "[REDACTED]", "email": "[REDACTED]"}, 1)
	if !r.Check() {
		t.Fatal("custom encoded fields escaped")
	}
}
