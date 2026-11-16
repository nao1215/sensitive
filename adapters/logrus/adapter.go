package embargologrus

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"

	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/internal/output"
	"github.com/nao1215/embargo/internal/saferecord"
)

// NewFormatter masks the complete JSON object returned by next.
// Both dependencies are required; nil dependencies panic.
// Invalid output, formatter failures, limits and cancellation return a diagnostic
// with the original time/level, a fixed reason and withheld_attributes. Format
// returns nil error for this diagnostic so logrus writes it. No original fields
// are retained. A nil entry returns a fixed error. See the package limits.
func NewFormatter(next logrus.Formatter, scanner *embargo.Scanner) logrus.Formatter {
	output.Require(next)
	output.Require(scanner)
	return &formatter{next: next, scanner: scanner}
}

type formatter struct {
	next    logrus.Formatter
	scanner *embargo.Scanner
}

// Format masks the completed JSON event or supplies a safe diagnostic.
func (f *formatter) Format(entry *logrus.Entry) (data []byte, err error) {
	if entry == nil {
		return nil, errors.New("embargo: logrus formatting failed")
	}
	ctx := entry.Context
	if ctx == nil {
		ctx = context.Background()
	}
	var cause error
	complete := false
	defer func() {
		_ = recover() //nolint:errcheck // Discard formatter panic values.
		if !complete {
			data = saferecord.JSON(entry.Time, entry.Level.String(), len(entry.Data), saferecord.Reason(ctx, cause))
			err = nil
		}
	}()
	if ctx.Err() != nil {
		return nil, nil
	}
	raw, formatErr := f.next.Format(entry)
	if formatErr != nil {
		return nil, nil
	}
	data, cause = output.JSONContext(ctx, raw, f.scanner)
	if cause != nil {
		return nil, nil
	}
	complete = true
	return data, nil
}
