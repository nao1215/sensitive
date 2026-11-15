# Values that must not be displayed

`Secret` prints `[REDACTED]` through fmt, slog, JSON and text encoding, including XML's text-marshaling path. `Reveal` deliberately returns the wrapped value. The wrapper suppresses display; it does not erase memory or control a value after Reveal.

| Operation | Result |
|---|---|
| `fmt.Sprint(embargo.NewSecret("fake-key"))` | `[REDACTED]` |
| JSON encoding of that Secret | `"[REDACTED]"` |
| `secret.Reveal()` | `fake-key` |

See the [runnable Secret Examples](../secret_example_test.go) and [actual encoder tests](../tests/compatibility_integration_test.go).

## Decode before publishing a Secret

`Input[string]` decodes JSON strings or text; `Input[[]byte]` uses JSON's base64 convention for byte slices. `Secret()` returns a snapshot unaffected by later decoding into the Input. Its decoding errors clear the stored value, including a rejected redaction marker.

Decode into a fresh object: absent fields and invalid outer JSON can prevent Input's decoder from being called. The [outer-object regression](../tests/input_lifecycle_test.go) demonstrates why reusing a populated object can retain an earlier value.

[Decoding contracts and regressions](../input_test.go), [Input Examples](../secret_example_test.go).

## Database and configuration inputs

`Input` already implements `encoding.TextUnmarshaler` for environment/configuration loaders that support that interface. `Input.Scan` implements `sql.Scanner` for database string and byte columns; the Input destination may use a named string or byte-slice type. Driver source values must be ordinary string or []byte values, or nil. It copies the driver's bytes before they can be reused; SQL NULL clears the value; unsupported source types and redaction markers clear it and return a fixed error. Use `rows.Scan(&input)` during initialization and publish `input.Secret()` afterwards. Concurrent mutation and observation of an Input are unsupported. A failed outer query or scan of another column can leave earlier columns assigned; discard the whole DTO on failure.

`Secret` stays an immutable snapshot and does not implement scanning or text unmarshaling. Neither wrapper implements `driver.Valuer`: implicitly returning its raw value would create an output path that bypasses the wrapper's display contract, while returning the marker could silently corrupt stored credentials. Write deliberately with `db.ExecContext(ctx, query, secret.Reveal())`. Use string/byte Input fields for secrets; arbitrary numeric or driver-specific SQL types need explicit conversion by the application. See the [runnable database Example](../structured_example_test.go) and [copy, NULL and failure tests](../input_sql_test.go).

## Migrating from struct tags

masq users do use tags in real applications, including [wandb/operator](https://github.com/wandb/operator/blob/7db584188fe7adae6e7cea58f62a51438630903e/internal/logx/redact.go) and [73ai/infralayer](https://github.com/73ai/infralayer/blob/9b28ed83ffcfb5fabd6673d120206cef723fa96e/services/backend/cmd/main.go). embargo deliberately does not add an `embargo:"secret"` tag. The zap, zerolog and logrus adapters see encoded bytes; they cannot recover Go tags. A slog-only tag would split the common output model. Furthermore, fmt, encoding/json, errors, panics, templates and other loggers ignore a masker-specific tag, and the original value remains exposed whenever it bypasses that masker. Another annotation is another thing to forget; this follows the decision to remove Catalog and Describe.

For a type you cannot change, migrate a tagged field to the shared key policy; use its JSON name if it has a JSON tag:

```go
// Before: the annotation is only interpreted by masq.
type Credentials struct {
    Recovery string `masq:"secret" json:"recovery"`
}
// After: every embargo logger adapter and MaskJSON uses this policy.
scanner := embargo.NewScanner(embargo.WithSensitiveKeys(
    "password", "passwd", "secret", "token", "api_key",
    "authorization", "cookie", "set-cookie", "recovery",
))
```

For a type you own, change the field type so the value protects itself even outside embargo:

```go
// Before.
type Credentials struct { Recovery string `masq:"secret"` }
// After.
type Credentials struct { Recovery embargo.Secret[string] }
credentials := Credentials{Recovery: embargo.NewSecret("synthetic-recovery-code")}
```

A database/config DTO can instead declare `Recovery embargo.Input[string]` and copy its Secret into the application's immutable Credentials after loading. Both wrappers mask themselves through fmt, encoding/json and their other supported formatting interfaces. This is not memory erasure or protection after an explicit Reveal, a custom formatter that ignores the interfaces, or a process memory dump. [Runnable Secret Examples](../secret_example_test.go) and [cross-encoder tests](../tests/compatibility_integration_test.go) define the supported paths.

[Support maintenance](https://github.com/sponsors/nao1215).

## Keep domain types independent of embargo

A domain package can implement standard output interfaces without importing embargo. The complete example below is compiled in `tests/domain`; `TestDomainValueContract` runs it through `embargotest.CheckValue` and both embargo slog encoders with detector selection disabled, so detection cannot conceal a missing method.

<!-- domain-value:start -->
```go
// Package domain demonstrates a secret type that imports only the standard library.
package domain

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
)

// Password is an application-owned credential with explicit output behavior.
type Password string

// String protects ordinary string formatting and templates.
func (Password) String() string { return "[REDACTED]" }

// GoString protects Go-syntax formatting.
func (Password) GoString() string { return "[REDACTED]" }

// Format protects every fmt verb, including quotes and hexadecimal.
func (Password) Format(state fmt.State, _ rune) {
	if _, err := io.WriteString(state, "[REDACTED]"); err != nil {
		return
	}
}

// LogValue protects a direct slog attribute.
func (Password) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON protects JSON leaves, including nested structured logger values.
func (Password) MarshalJSON() ([]byte, error) { return json.Marshal("[REDACTED]") }

// MarshalText protects text encoding; JSON bypasses it for string-typed map keys.
func (Password) MarshalText() ([]byte, error) { return []byte("[REDACTED]"), nil }

// MarshalXML protects XML element content.
func (Password) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement("[REDACTED]", start)
}
```
<!-- domain-value:end -->

| Method | Covered output | Boundary |
|---|---|---|
| String | Ordinary fmt string output and templates | `%#v` uses GoString; a formatter can supersede String |
| GoString | `%#v` | Does not protect JSON or slog |
| Format | `%v`, `%+v`, `%#v`, `%s`, `%q`, `%x` | fmt itself handles `%T` and `%p` |
| LogValue | Direct slog attributes, including embargo's handler | Nested JSON fields do not call LogValue |
| MarshalJSON | JSON values, nested structs/maps and JSON-based logger paths | String-typed JSON map keys bypass both marshaling methods |
| MarshalText | Text encoders and XML fallback | JSON calls this for non-string map-key types; string kinds take precedence |
| MarshalXML | XML element content | Does not protect another serialization format |

The embargo handler resolves direct LogValuer values and honors encoding/json's MarshalJSON and MarshalText rules for structured values. Adapters inspect the bytes their logger actually encoded; they honor methods that logger invokes and cannot invent missing method calls. embargotest observes the resulting bytes. `CheckValue(t, func(canary string) any { return Password(canary) })` checks all supported formatter paths and names each path that leaks or cannot be exercised. It also checks Secret and Input in this repository. Homemade types often omit `%#v`, `%+v`, `%q`, MarshalText or LogValue; Secret exists to maintain that contract for users who want it.

A plain string or struct remains supported: the sensitive-key rule and detectors provide the net for values that have neither a wrapper nor formatting methods. No formatter contract protects an explicit conversion such as `string(password)`, a deliberate Reveal, or a debugger memory dump.

CheckValue exercises values, not map keys. In particular, encoding/json reads a defined string type used as a map key directly, even when it implements MarshalText; `map[Password]string` therefore exposes the underlying key. Keep secrets out of map keys, or use a comparable struct wrapper with MarshalText such as Secret. This is a standard-library dispatch rule that an output adapter cannot change before encoding; detectors remain a separate safeguard.
