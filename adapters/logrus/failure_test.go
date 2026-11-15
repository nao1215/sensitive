package embargologrus_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/nao1215/embargo"
	embargologrus "github.com/nao1215/embargo/adapters/logrus"
)

type brokenFormatter struct{ panicValue bool }

func (f brokenFormatter) Format(*logrus.Entry) ([]byte, error) {
	if f.panicValue {
		panic("public-fake-canary")
	}
	return []byte("public-fake-canary"), errors.New("public-fake-canary")
}

func TestFormatterErrorsAndUnsupportedTextFailClosed(t *testing.T) {
	t.Parallel()
	for _, next := range []logrus.Formatter{brokenFormatter{}, brokenFormatter{panicValue: true}, &logrus.TextFormatter{DisableTimestamp: true}} {
		formatter := embargologrus.NewFormatter(next, embargo.NewScanner())
		entry := &logrus.Entry{Message: "public-fake-canary", Level: logrus.InfoLevel}
		data, err := formatter.Format(entry)
		if data != nil || err == nil || strings.Contains(err.Error(), "canary") {
			t.Fatal("unsafe formatting failure")
		}
		if entry.Message != "public-fake-canary" {
			t.Fatal("entry mutated")
		}
	}
}
