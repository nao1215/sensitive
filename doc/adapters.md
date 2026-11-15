# Logger adapters

These optional modules mask at the final JSON boundary, after the real logger has called object/array marshalers and encoded With/context fields. The shared internal/output parser belongs to the dependency-free root module and imports only the root scanner and standard library. Each adapter module owns its SDK requirements. The root go.mod has no require directives.

## Installation

Until the owner publishes adapter releases, select the required module from main:

```sh
go get github.com/nao1215/embargo/adapters/zap@latest
go get github.com/nao1215/embargo/adapters/zerolog@latest
go get github.com/nao1215/embargo/adapters/logrus@latest
```

Use only the module for your logger. The [zap](../adapters/zap/example_test.go), [zerolog](../adapters/zerolog/example_test.go) and [logrus](../adapters/logrus/example_test.go) Examples show complete setup and their actual JSON output.

## API

| Package | Public API | Why this boundary |
|---|---|---|
| embargozap | NewWriteSyncer(next zapcore.WriteSyncer, scanner *embargo.Scanner) zapcore.WriteSyncer | [Explanation 1](#table-explanation-1) |
| embargozerolog | NewWriter(next io.Writer, scanner *embargo.Scanner) io.WriteCloser | [Explanation 2](#table-explanation-2) |
| embargologrus | NewFormatter(next logrus.Formatter, scanner *embargo.Scanner) logrus.Formatter | [Explanation 3](#table-explanation-3) |

All constructors require non-nil dependencies, including typed-nil checks, and panic with a fixed message on invalid configuration. Scanner policy is explicit. The adapters add no public option types or configuration objects.

## Output and failure contracts

JSON keys, decoded string values and the literal rendering of JSON numbers are scanned. Clean numbers, booleans and null remain typed; a matched numeric value becomes a redaction string. Nested arrays/objects and duplicate keys are retained. JSON escapes are decoded before scanning, so an escaped at-sign does not hide an email. Each event is limited to 1 MiB, 64 nesting levels and 4 MiB of cumulative scanner input, counting repeated field-name context; the stream writers include the newline in their byte budget. No partial record is forwarded. Invalid, oversized or incomplete JSON and scanner panics fail with fixed errors, including panic(nil) compatibility mode.

The stream writer serializes calls and retains the first parse/write failure. Whole-event concurrent writes are supported; interleaving fragments from different events is not a supported framing protocol. Earlier complete records may already have been sent when a later record fails. Sink errors and short writes are returned; a sink can partially write already masked bytes. Finish producers before Sync/Close. Close seals zerolog's adapter but does not close its sink. Zap Sync checks completeness and delegates synchronization without closing. Logrus formatter errors/panics suppress output with a fixed error that does not include formatter data.

## Limits exercised by tests

- The stream writers accept newline-delimited JSON objects; the logrus formatter accepts one JSON object. Zap console encoding, zerolog CBOR/binary builds or a ConsoleWriter before the adapter, and logrus TextFormatter fail closed. Place human-readable rendering after a masked JSON stream if needed.
- Base64 binary fields (zap Binary and logrus byte slices), zerolog Hex, compression, encryption and application-defined encodings are not decoded. Negative-control tests write an encoded canary through each real logger and require embargotest to detect the leak. Use Secret before the logger encodes those values, or add an application detector for the encoded form.
- Only the connected sink/formatter is covered. Zap ErrorOutput, logger hooks with independent destinations, other cores, downstream code that adds data and values reconstructed from separate fields need their own observation or masking policy.
- Detection has the scanner's documented precision/recall limits. A canary is not automatically a runtime pattern: the positive tests register a literal detector for it, independently of embargotest's canary checks.

The public Examples run real loggers with Output comments. Tests inspect message, key, string, numeric, Secret, pre-bound and nested output through embargotest. Shared boundary tests cover split writes, bounds, malformed/deep JSON, duplicate keys, short writes, concurrency and panic(nil). All three modules run on Linux, macOS and Windows at the minimum and stable Go versions, with strict lint and vulnerability checks.

## Versions

Each adapter is its own module with its own tag (adapters/zap/vX.Y.Z, adapters/zerolog/vX.Y.Z, adapters/logrus/vX.Y.Z) and requires the matching root release. The local replace directives are used only for development and CI; downstream builds ignore them.

## Shared JSON policy

The adapters use the same `Scanner.MaskJSON` engine as structured slog Any values. It masks decoded string leaves and object keys, preserves clean numeric lexemes without float64 conversion, and replaces the entire value of a sensitive key. `WithSensitiveKeys` therefore covers third-party structs, maps and HTTP headers after their logger encodes them, including custom marshaler output. See [the logging model and limits](logging.md) and [tag migration](values.md). Embargo's root module still has zero requirements; logger SDKs and comparison libraries stay in optional/test modules.

## Table explanations

<a id="table-explanation-1"></a>

Fits zapcore.NewCore with a JSON encoder and inspects the actual representation of every field type; Sync validates buffered output and delegates to the sink.

<a id="table-explanation-2"></a>

A Hook cannot remove fields already encoded in an Event. The writer buffers split JSON records and Close rejects an incomplete record without closing the caller-owned sink.

<a id="table-explanation-3"></a>

Wraps JSONFormatter after it formats the Entry, without modifying caller-owned fields or trusting a second serialization of an arbitrary value.
