# Keep your masking, add the leak test

You can keep masq, another masking library, or an application-owned masking function and use embargotest only in tests. A recorder observes the bytes your existing logger emits; it does not mask them. A planted canary catches leaks independently of the detector rules, and an output expectation prevents an empty logger from passing.

Add the test dependency with `go get github.com/nao1215/embargo/embargotest@v0.19.0`. The package adds no external dependencies. Paste this into an existing package's test file; production code needs no embargo import:

```go
package example

import (
    "log/slog"
    "testing"

    "github.com/nao1215/embargo/embargotest"
)

func TestExistingMasking(t *testing.T) {
    recorder := embargotest.New(t)
    existing := &slog.HandlerOptions{ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
        if attr.Key == "token" {
            return slog.String(attr.Key, "[REDACTED]")
        }
        return attr
    }}
    logger := slog.New(slog.NewJSONHandler(recorder.Writer("logs"), existing))
    logger.Info("accepted", "token", string(recorder.Canary()))
    recorder.ExpectJSON("logs", nil, map[string]string{"msg": "accepted", "token": "[REDACTED]"}, 1)
    recorder.Check()
}
```

Run `go test ./...`. The [runnable example](../embargotest/example_test.go) executes this policy and checks the same output. Replace `existing` with your masq ReplaceAttr or application's handler options. Remove the token replacement to see the test fail; the failure diagnostic does not print the planted canary. Checking the expected marker also catches a change to the masking contract.

For a handler or service, pass `recorder.Canary()` into the actual request, configuration or dependency that normally supplies the secret, then direct the application's real output sink to `recorder.Writer("logs")`. Testing a separate toy formatter does not test your application's path. The recorder also scans for supported sensitive values, so use public synthetic data and explicit allowances for intentional values. It cannot identify an arbitrary unknown secret unless it is planted as a canary or matches a configured detector.

Use `embargotest.Guard` in TestMain when you also need package stdout, stderr, default slog and inherited child-process output. Use `recorder.HTTP` to inspect responses, including headers and trailers; a logger cannot cover a secret sent only in an HTTP response. See [output tests](testing-output.md) for lifecycle rules and [scanner configuration](../README.md#find-and-mask-sensitive-text) for detector selection.
