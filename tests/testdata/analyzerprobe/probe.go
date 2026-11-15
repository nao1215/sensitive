package analyzerprobe

import (
	"github.com/nao1215/embargo"
	"github.com/nao1215/embargo/tests/domain"
	"log/slog"
)

func raw(password string, cfg struct{ Token string }) {
	slog.Info("failure", "value", password)  // true positive
	slog.Info("failure", "value", cfg.Token) // true positive
}
func safe(password domain.Password, token embargo.Input[string], secret string) {
	slog.Info("safe", "value", password)                                                                                   // false positive: standard interfaces hide it
	slog.Info("safe", "value", token)                                                                                      // false positive: Input hides it
	slog.New(embargo.NewSlogHandler(slog.NewJSONHandler(nil, nil), embargo.NewScanner())).Info("safe", "password", secret) // false positive: masking handler owns policy
}
func wrapped(password embargo.Secret[string]) { slog.Info("safe", "value", password) }
func renamed(data string)                     { slog.Info("leak", "value", data) } // false negative: opaque name
