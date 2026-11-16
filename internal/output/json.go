package output

import (
	"bytes"
	"context"
	"errors"

	"github.com/nao1215/embargo"
)

const maxEventBytes = 1 << 20

func failure() error { return errors.New("embargo: invalid or unmaskable JSON log event") }

// JSON masks a JSON log object through the shared policy, preserving its shape.
// The adapter includes the final newline in its 1 MiB event limit.
func JSON(data []byte, scanner *embargo.Scanner) ([]byte, error) {
	return JSONContext(context.Background(), data, scanner)
}

// JSONContext keeps JSON framing while stopping canceled scalar and detector scans.
func JSONContext(ctx context.Context, data []byte, scanner *embargo.Scanner) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || len(data) > maxEventBytes {
		return nil, failure()
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, failure()
	}
	masked, err := scanner.MaskJSONContext(ctx, data)
	if err != nil || len(masked) >= maxEventBytes {
		return nil, failure()
	}
	return append(masked, '\n'), nil
}
