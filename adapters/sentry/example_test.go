package embargosentry_test

import (
	"fmt"

	"github.com/getsentry/sentry-go"

	"github.com/nao1215/embargo"
	embargosentry "github.com/nao1215/embargo/adapters/sentry"
)

func ExampleNewBeforeSend() {
	beforeSend := embargosentry.NewBeforeSend(embargo.NewScanner())
	event := sentry.NewEvent()
	event.Message = "alice@example.com could not sign in"
	event.Contexts = map[string]sentry.Context{"login": {"password": "opaque-password"}}
	safe := beforeSend(event, nil)
	fmt.Println(safe.Message)
	fmt.Println(safe.Contexts["login"]["password"])
	// Output:
	// [REDACTED] could not sign in
	// [REDACTED]
}
