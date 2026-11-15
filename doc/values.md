# Values that must not be displayed

`Secret` prints `[REDACTED]` through ordinary fmt, slog, JSON and text encoding, including XML's text-marshaling path. Go-syntax formatting (`%#v`) includes the instantiated type: `embargo.Secret[string]([REDACTED])`. `Reveal` deliberately returns the wrapped value. The wrapper suppresses display; it does not erase memory or control a value after Reveal.

| Operation | Result |
|---|---|
| `fmt.Sprint(embargo.NewSecret("fake-key"))` | `[REDACTED]` |
| `fmt.Sprintf("%#v", embargo.NewSecret("fake-key"))` | `embargo.Secret[string]([REDACTED])` |
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

A domain package can implement standard output interfaces without importing embargo. Use a struct containing an unexported pointer: fmt expands an unexported string field without calling String or Format, even when the defined string type implements every output method. The complete example below is compiled in `tests/domain`; `TestDomainValueContract` runs it through `embargotest.CheckValue` and both embargo slog encoders with detector selection disabled, so detection cannot conceal a missing method.

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

// Password keeps credential storage behind an unexported pointer.
type Password struct{ value *string }

// NewPassword keeps fmt from expanding the raw string inside an unexported field.
func NewPassword(value string) Password { return Password{value: &value} }

// String supplies the display marker to fmt and templates.
func (Password) String() string { return "[REDACTED]" }

// GoString also hides the value in Go-syntax output.
func (Password) GoString() string { return "[REDACTED]" }

// Format ignores the requested representation and writes the marker.
func (Password) Format(state fmt.State, _ rune) {
	if _, err := io.WriteString(state, "[REDACTED]"); err != nil {
		return
	}
}

// LogValue gives slog a plain redacted string.
func (Password) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON stores a JSON marker string; this encoding cannot restore the password.
func (Password) MarshalJSON() ([]byte, error) { return json.Marshal("[REDACTED]") }

// MarshalText writes the marker in text encoders and JSON map keys.
func (Password) MarshalText() ([]byte, error) { return []byte("[REDACTED]"), nil }

// MarshalXML emits a marker inside the requested XML element.
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

The embargo handler resolves direct LogValuer values and honors encoding/json's MarshalJSON and MarshalText rules for structured values. Adapters inspect the bytes their logger actually encoded; they honor methods that logger invokes and cannot invent missing method calls. embargotest observes the resulting bytes. `CheckValue(t, func(canary string) any { return domain.NewPassword(canary) })` checks all supported formatter paths and names each path that leaks or cannot be exercised. It also checks Secret and Input in this repository. Homemade types often omit `%#v`, `%+v`, `%q`, MarshalText or LogValue; Secret exists to maintain that contract for users who want it.

A plain string or struct remains supported: the sensitive-key rule and detectors provide the net for values that have neither a wrapper nor formatting methods. No formatter contract protects an explicit conversion of a defined string type, a deliberate Reveal, or a debugger memory dump.

CheckValue exercises values, not map keys. In particular, encoding/json reads a defined string type used as a map key directly, even when it implements MarshalText; a map keyed by that string type therefore exposes its underlying key. Keep secrets out of map keys, or use a comparable struct wrapper with MarshalText such as Secret. This is a standard-library dispatch rule that an output adapter cannot change before encoding; detectors remain a separate safeguard.

## Audit disclosure sites

List explicit disclosures before reviewing a boundary:

```sh
rg -n --glob '*.go' '\.Reveal\s*\(' .
```

For each call, trace the returned string or bytes to its destination: an authentication header, database write or cryptographic operation may need them; logs, errors and diagnostic exports usually do not. Also search `.Reveal` method values and wrappers around them; the call-site search alone does not follow aliases or prove that a revealed copy stays private. Keep the original Secret in application state and pass the revealed value only where required.

## Encoding is not persistence

`MarshalJSON` and `MarshalText` write the marker. Saving `json.Marshal(credentials)` with a Secret field stores `"[REDACTED]"`, not an encrypted or recoverable value. The original value is lost from that serialized copy. Input rejects the marker on decode so it cannot silently become a password. Persist a deliberately revealed value through an appropriate storage boundary when that is the intended operation; serializing a Secret is a display safeguard.

A homemade `type Password string` with only `String()` can look safe at the top level and still expose its underlying string through `fmt.Sprint(struct{ password Password }{...})`. fmt does not call methods on unexported fields. [The regression test](../secret_debug_test.go) contrasts that case with Secret's pointer storage. CheckValue now covers `%v`, `%+v` and `%#v` inside such a field, so the incomplete type fails with a path such as `fmt/unexported/%v`. The domain example above uses the same storage principle without importing embargo.

## Memory lifetime

Secret does not erase its referent. Go may retain copies in stacks, registers, immutable strings and the heap, and clearing a byte slice cannot prove that every copy disappeared. Rust's [zeroize](https://docs.rs/zeroize/latest/zeroize/) supplies explicit zeroing for supported owned values; this wrapper does not offer an equivalent guarantee.

Go 1.26 has an experimental [runtime/secret.Do](https://pkg.go.dev/runtime/secret) facility for temporary storage, enabled with `GOEXPERIMENT=runtimesecret`. The [Go 1.26 release notes](https://go.dev/doc/go1.26) limit support to Linux on amd64 and arm64. The package has no Go 1 compatibility promise, and heap cleanup can wait until the garbage collector finds allocations unreachable. embargo does not import it or require that experiment; enabling it does not make Secret erase existing values or copies already handed to other code.
