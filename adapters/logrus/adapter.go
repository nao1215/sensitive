package embargologrus

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/output"
)

// NewFormatter masks the complete JSON object returned by next.
// Both dependencies are required; nil dependencies panic.
// Invalid output and formatter errors or panics return fixed errors without
// values. See the package documentation for framing and encoded-binary limits.
func NewFormatter(next logrus.Formatter, scanner *embargo.Scanner) logrus.Formatter {
	output.Require(next)
	output.Require(scanner)
	return &formatter{next: next, scanner: scanner}
}

type formatter struct {
	next    logrus.Formatter
	scanner *embargo.Scanner
}

// Format masks the completed JSON event and returns a fixed error on failure.
func (f *formatter) Format(entry *logrus.Entry) (data []byte, err error) {
	complete := false
	defer func() {
		_ = recover() //nolint:errcheck // Never expose a formatter panic value, including panic(nil).
		if !complete {
			data = nil
			err = errors.New("embargo: logrus formatting failed")
		}
	}()
	ctx := context.Background()
	if entry != nil && entry.Context != nil {
		ctx = entry.Context
	}
	if ctx.Err() != nil {
		return nil, errors.New("embargo: logrus formatting failed")
	}
	raw, formatErr := f.next.Format(entry)
	if formatErr != nil {
		return nil, errors.New("embargo: logrus formatting failed")
	}
	data, err = output.JSONContext(ctx, raw, f.scanner)
	complete = true
	return data, err
}
