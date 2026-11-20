---
title: Getting started
description: Keep values from printing, mask slog and other loggers, choose detectors, and fail tests when a secret reaches the output.
toc: true
---

## Values that must never print

<!-- example: example_test.go:ExampleNewSecret -->
```go
key := embargo.NewSecret("fake-key")

fmt.Println(key)

// Output: [REDACTED]
```

`Secret` prints `[REDACTED]` through fmt, slog, JSON, XML and text encoding, and `%#v` prints `embargo.Secret[string]([REDACTED])`. `Reveal` returns the value; use it only where the value is needed, such as an authentication header or a database write. Find those places with `rg -n --glob '*.go' '\.Reveal\s*\(' .`.

`Input` decodes a secret from JSON, text, configuration loaders that use `encoding.TextUnmarshaler`, and database columns, then hands out a `Secret`:

<!-- example: example_test.go:ExampleInput_UnmarshalJSON -->
```go
var config struct {
	Token embargo.Input[string] `json:"token"`
}
if err := json.Unmarshal([]byte(`{"token":"fake-key"}`), &config); err != nil {
	panic(err)
}

fmt.Println(config.Token.Secret())

// Output: [REDACTED]
```

- Decode into a fresh value. An absent field does not call the decoder, so a reused object keeps its old value; a failed decode clears it.
- `Input.Scan` implements `sql.Scanner` and copies the driver's bytes; SQL NULL clears the value. Neither type implements `driver.Valuer`, so write with `secret.Reveal()` on purpose.
- Encoding writes the marker, so `json.Marshal` of a struct with a `Secret` stores `"[REDACTED]"`, not the value, and `Input` refuses to decode the marker back.
- `Secret` does not erase memory. Go may keep copies on stacks and in the heap, and embargo does not use the experimental `runtime/secret`.

embargo reads no struct tags: a tag only works inside the masker that reads it, while fmt, encoding/json, errors and other loggers ignore it. Make the field a `Secret` when you own the type, or name its key with `WithSensitiveKeys` when you do not. A domain package can also hide a value without importing embargo by implementing `String`, `GoString`, `Format`, `LogValue`, `MarshalJSON`, `MarshalText` and `MarshalXML` on a struct with an unexported pointer, as [tests/domain/password.go](tests/domain/password.go) does; `embargotest.CheckValue` checks such a type on every formatter path. A defined string type used as a JSON map key is printed as is, even with `MarshalText`.

## Mask slog output

Wrap the handler you already use. Messages, keys, group names and values are scanned before they reach it.

<!-- example: example_test.go:ExampleNewSlogHandler_struct -->
```go
// An existing type: no tags, no embargo field types.
type User struct {
	Name     string
	Email    string
	Password string
}
logger := slog.New(embargo.NewSlogHandler(next, embargo.NewScanner()))

logger.Info("signup", "user", User{Name: "carol", Email: "carol@example.com", Password: "hunter2"})

// Output: {"level":"INFO","msg":"signup","user":{"Name":"carol","Email":"[REDACTED]","Password":"[REDACTED]"}}
```

Wrap `next` before calling `With` on it: attributes bound to `next` itself never pass through embargo.

The JSON keeps its shape, so field filters and range queries in Loki, Datadog, CloudWatch or BigQuery keep working:

| Value | Written as |
|---|---|
| Clean string, number, bool or null | The original value and type |
| String with a secret inside | The same string with only that part replaced |
| Number that is a secret, such as a card number | A marker string |
| Any value under a sensitive key, including objects and arrays | `[REDACTED]` |
| Struct, map or slice | Encoded with encoding/json, then masked leaf by leaf |
| `[]byte` | Its text scanned before base64 encoding |
| error | Its `Error()` text, scanned |

Structured values go through encoding/json as `slog.JSONHandler` does, so JSON tags, `json:"-"` and custom `MarshalJSON` behave as usual. `LogValuer` values are resolved first, up to 100 times. Numbers are compared as exact integers without float rounding.

### Sensitive keys

The values of `password`, `passwd`, `secret`, `token`, `api_key`, `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `access_token`, `refresh_token`, `id_token`, `x-api-key`, `DB_PASSWORD`, `Private-Token`, `client_secret`, `auth_token`, `PGPASSWORD`, `otp`, `pin`, `passcode`, `passphrase`, `session`, `sessionid`, `session_token`, `JSESSIONID`, `PHPSESSID`, `pass` and `pwd` are hidden whatever they hold. Matching ignores ASCII case and `_`, `-`, `.` and space, so `apiKey` matches `api_key`. A name whose last segment is password, passwd, secret, token, credential or auth also matches, as does key after api, secret, private, access, account, auth or master: `POSTGRES_PASSWORD` and `X-Auth-Key` match, `primary_key` and `token_count` do not.

<!-- example: example_test.go:ExampleWithSensitiveKeys -->
```go
scanner := embargo.NewScanner(embargo.WithKinds(), embargo.WithSensitiveKeys("recovery_code"))
safe, err := scanner.MaskJSON([]byte(`{"recoveryCode":"opaque","api-key":"opaque","count":3}`))
if err != nil {
	panic(err)
}
fmt.Println(string(safe))
// Output:
// {"recoveryCode":"[REDACTED]","api-key":"[REDACTED]","count":3}
```

`WithSensitiveKeys` adds names; `WithoutDefaultSensitiveKeys` drops the defaults and the suffix rule. A group with a sensitive name is replaced as a whole. In a name/value pair such as `{"name":"DB_PASSWORD","value":"..."}`, the value is hidden when the name is sensitive. Credential assignments in raw text, such as `recovery=opaque`, follow the same keys when `KindCredential` is selected.

### JSON outside logging

<!-- example: example_test.go:ExampleScanner_MaskJSON -->
```go
scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail))
// Sanitize an audit export before uploading it to a support system.
safe, err := scanner.MaskJSON([]byte(`{"user":{"email":"alice@example.com","password":"opaque"},"amount":125,"paid":true}`))
if err != nil {
	panic(err)
}
fmt.Println(string(safe))
// Output:
// {"user":{"email":"[REDACTED]","password":"[REDACTED]"},"amount":125,"paid":true}
```

MaskJSON applies the same policy to API responses, audit exports and support bundles. Duplicate keys and their order are kept, and base64 text up to 8 KiB is decoded once and scanned.

## Loggers and services

| Logger or service | Wrap it with |
|---|---|
| log/slog, any slog.Handler | `embargo.NewSlogHandler(next, scanner)` |
| go.uber.org/zap | [`embargozap.NewWriteSyncer(next, scanner)`](adapters/zap/example_test.go) |
| github.com/rs/zerolog | [`embargozerolog.NewWriter(next, scanner)`](adapters/zerolog/example_test.go) |
| github.com/sirupsen/logrus | [`embargologrus.NewFormatter(next, scanner)`](adapters/logrus/example_test.go) |
| net/http server access log | `embargo.NewHTTPHandler(next, logger, scanner)` |
| gRPC server, unary and stream | [`embargogrpc.NewUnaryServerInterceptor(logger, scanner)`](adapters/grpc/example_test.go), `NewStreamServerInterceptor` |
| OpenTelemetry SDK logs and spans | [`embargootel.NewLogExporter(next, scanner)`](adapters/otel/example_test.go), `NewSpanExporter` |
| Sentry events | [`embargosentry.NewBeforeSend(scanner)`](adapters/sentry/example_test.go) |
| log, fmt and anything else | `Secret` values, or `embargo.Mask` on the text before writing |

<!-- example: example_test.go:ExampleNewHTTPHandler -->
```go
var logs bytes.Buffer
logger := slog.New(slog.NewJSONHandler(&logs, nil))
next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
handler := embargo.NewHTTPHandler(next, logger, embargo.NewScanner())
request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/profile?email=alice@example.com", http.NoBody)
response := httptest.NewRecorder()
handler.ServeHTTP(response, request)
var event struct {
	Target string `json:"target"`
}
if err := json.Unmarshal(logs.Bytes(), &event); err != nil {
	panic(err)
}
fmt.Println(response.Code)
fmt.Println(event.Target)
// Output:
// 204
// /profile?email=[REDACTED]
```

- The HTTP and gRPC hooks mask what they log, not the request or response. `Authorization`, `Cookie` and `Set-Cookie` are always hidden in the access record; other headers and query keys follow the sensitive keys. Bodies and gRPC messages are not logged.
- gin, echo and Connect servers are `http.Handler` values, so `NewHTTPHandler` wraps them without a framework adapter; [TestWebFrameworkAccessLogs](tests/integrations_test.go) runs gin, echo and Connect this way. Leave the framework's own logger middleware off, since it writes outside slog.
- The zap, zerolog and logrus adapters mask the JSON the logger encoded, so they see `With` fields and custom marshalers. They need the JSON encoder: zap console encoding, zerolog's ConsoleWriter in front of the adapter, and logrus TextFormatter are refused.
- OpenTelemetry exporters mask bodies, attributes, span names, events, links and status descriptions, and drop TraceState. Sentry's `BeforeSend` masks a copy of the event and drops attachments.
- Access logs usually need the client address. Select kinds without `KindIPAddr`, as [ExampleWithKinds_accessLog](example_test.go) does.

### Bounds and failures

One encoded value is limited to 1 MiB, 64 levels of nesting and 4 MiB of detector input. When masking fails or a limit is reached, the record is replaced, not dropped: the time and level stay, the message becomes `embargo: record withheld (masking error)`, `embargo: record withheld (size limit)` or `embargo: record withheld (canceled)`, and the only attribute is the integer `withheld_attributes`. Nothing of the original message, keys or values remains, so watch for that message at the sink.

- The limits bound encoded bytes, not the time spent in `MarshalJSON`, `LogValue`, `String` or `Error`. Use `Secret` or a bounded `LogValuer` for expensive or untrusted types.
- `Handle` checks its context between detectors; a running detector or marshaler cannot be interrupted. A request already canceled when its access record is built gets 100 ms to mask it.
- net/http writes handler panics through `Server.ErrorLog`; set it to `slog.NewLogLogger(logger.Handler(), slog.LevelError)`.
- The zap and zerolog writers have no context. They write a diagnostic for invalid or oversized JSON and resume at the next newline. OpenTelemetry and Sentry replace only the record that failed.

## Choose what is detected

`Scan` takes bytes, `ScanString` text and `ScanLines` independent lines. A finding holds the kind, a confidence and byte offsets in the original input. `NewScanner()` runs 19 built-ins at minimum confidence 0. One country's formats, SWIFT/BIC and merchant IDs, and `KindHighEntropy` are opt-in: `WithMoreKinds` adds kinds to the default, `WithKinds` replaces them, and `WithAll` selects all 39. [Kinds](/kinds/) lists them and what each matches.

<!-- masking:start -->
| Operation | Actual text |
|---|---|
| Input | `INFO checkout email=alice@example.com card=4111111111111111` |
| [Mask](example_test.go) | `INFO checkout email=[REDACTED] card=[REDACTED]` |
| [MaskFunc: keep last four](example_test.go) | `INFO checkout email=[REDACTED] card=[REDACTED]1111` |
| [Overlapping matches](example_test.go) | `token=abcdef` with `abcd cdef` → `token=[REDACTED]` |
<!-- masking:end -->

`Mask` replaces overlapping findings once, so the end of either match cannot escape. `WithMaskFunc` chooses the replacement everywhere the scanner masks, including the slog handler, MaskJSON and the adapters:

<!-- example: example_test.go:ExampleWithMaskFunc -->
```go
next := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
	ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	},
})
lastFour := func(kind embargo.Kind, value string) string {
	if kind != embargo.KindPAN {
		return "[" + strings.ToUpper(string(kind)) + "]"
	}
	return "****" + value[len(value)-4:]
}
scanner := embargo.NewScanner(embargo.WithKinds(embargo.KindEmail, embargo.KindPAN), embargo.WithMaskFunc(lastFour))
logger := slog.New(embargo.NewSlogHandler(next, scanner))

logger.Info("checkout", "email", "alice@example.com", "card", "4532015112830366", "password", "hunter2")

// Output: {"level":"INFO","msg":"checkout","email":"[EMAIL]","card":"****0366","password":"[REDACTED]"}
```

Values under sensitive keys, encoded text that decodes to a finding and withheld records still become `[REDACTED]`, and a replacement that contains the whole value falls back to it. For an application-specific pattern, implement `Detector` and pass it to `WithDetector`; it must return ranges inside its input with confidences from 0 to 1, and be safe for concurrent calls.

## Fail tests on leaks

Add one line to a package's tests:

`func TestMain(m *testing.M) { os.Exit(embargotest.Guard(m)) }`

Guard runs the package tests again under a supervisor and fails when a fake secret, in any common encoding, or a detected value appears in stdout, stderr, the default slog logger, `t.Log` output or child processes. The default limit is 1 MiB and five minutes; `WithMaxBytes` and `WithTimeout` raise it.

For one test, a recorder checks that the expected output is there and the planted canary is not:

<!-- test: doc_test.go:TestReadmeCheckOutput -->
```go
func TestReadmeCheckOutput(t *testing.T) {
    t.Parallel()
    recorder := embargotest.New(t)
    next := slog.NewJSONHandler(recorder.Writer("logs"), nil)
    // Wrap next first; attributes bound with next.WithAttrs would skip embargo.
    logger := slog.New(embargo.NewSlogHandler(next, embargo.NewScanner())).With("api_token", string(recorder.Canary()))

    logger.Info("accepted", "email", "alice@example.com")

    recorder.ExpectJSON("logs", nil, map[string]string{"msg": "accepted", "email": "[REDACTED]"}, 1)
    recorder.Check()
}
```

You can keep masq, another masking library or your own masking function and use embargotest only in tests: the recorder observes the bytes your logger writes and does not mask them, as [ExampleRecorder_existingMasking](embargotest/example_test.go) shows. Pass `recorder.Canary()` through the real input that normally carries the secret, such as a header, an environment variable or a config file, and point the real sink at `recorder.Writer("logs")`.

| Connect | To |
|---|---|
| A logger or encoder | `recorder.Writer("logs")` |
| An HTTP handler | `recorder.HTTP("http")`, which checks status, headers, body and trailers |
| A child process of the test binary | `recorder.Run(ctx, "TestHelper", exitCode)` |

| Check | Independent of the detectors? |
|---|---|
| The whole canary, raw or in hex, base64, JSON, Go quoting or decimal bytes | Yes |
| `WithCanaryFragments(16)`: any raw piece of the canary of 16 bytes or more | Yes |
| A detector scan of the output | No: a value both sides miss passes |
| `Expect` and `ExpectJSON` | You choose what must survive, such as an order ID |

A recorder with no output or no expectation fails, so an empty logger cannot pass. The recorder and Guard scan with the same 19 built-ins as `NewScanner()`; one country's formats and `KindHighEntropy` are opt-in through `WithScanner(embargo.NewScanner(embargo.WithAll()))`. `WithAllowedKinds` and `WithAllowedValues` allow deliberate fixture content, and the canary check stays on. A pass does not cover truncated, hashed or split output, or output outside the captured sinks.
