package output

import (
	"bytes"
	"errors"

	"github.com/nao1215/embargo"
)

const maxEventBytes = 1 << 20

func failure() error { return errors.New("embargo: invalid or unmaskable JSON log event") }

// JSON masks a JSON log object through the shared policy, preserving its shape.
// The adapter includes the final newline in its 1 MiB event limit.
func JSON(data []byte, scanner *embargo.Scanner) ([]byte, error) {
	if len(data) > maxEventBytes {
		return nil, failure()
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return nil, failure()
	}
	masked, err := scanner.MaskJSON(data)
	if err != nil || len(masked) >= maxEventBytes {
		return nil, failure()
	}
	return append(masked, '\n'), nil
}
