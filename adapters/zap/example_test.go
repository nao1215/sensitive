package embargozap_test

import (
	"bytes"
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/nao1215/embargo"
	embargozap "github.com/nao1215/embargo/adapters/zap"
)

func ExampleNewWriteSyncer() {
	var output bytes.Buffer
	sink := embargozap.NewWriteSyncer(zapcore.AddSync(&output), embargo.NewScanner(embargo.WithKinds(embargo.KindEmail)))
	//nolint:goconst // The runnable Example shows the encoder configuration in full.
	logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zapcore.EncoderConfig{MessageKey: "msg"}), sink, zap.InfoLevel))

	logger.Info("checkout", zap.String("email", "alice@example.com"))
	if err := logger.Sync(); err != nil {
		panic(err)
	}

	fmt.Print(output.String())

	// Output: {"msg":"checkout","email":"[REDACTED]"}
}
