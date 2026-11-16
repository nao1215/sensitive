# Logger adapters

These optional modules mask at the final JSON boundary, after the real logger has called object/array marshalers and encoded With/context fields. The shared internal/output parser belongs to the dependency-free root module and imports only the root scanner and standard library. Each adapter module owns its SDK requirements. The root go.mod has no require directives.

## Installation

The six adapter modules are published at v0.5.2 and require root v0.5.2. Upgrade the root and every installed adapter to receive the adjacent-match masking fixes in [v0.5.2](../CHANGELOG.md#052---2026-11-16). Install the module for the logger or SDK the application uses:

```sh
go get github.com/nao1215/embargo/adapters/zap@v0.5.2
go get github.com/nao1215/embargo/adapters/zerolog@v0.5.2
go get github.com/nao1215/embargo/adapters/logrus@v0.5.2
go get github.com/nao1215/embargo/adapters/grpc@v0.5.2
go get github.com/nao1215/embargo/adapters/otel@v0.5.2
go get github.com/nao1215/embargo/adapters/sentry@v0.5.2
```

For `NewHTTPHandler`, install the root module with `go get github.com/nao1215/embargo@v0.5.2`; no adapter module is needed.

Use only the module for your integration. The [zap](../adapters/zap/example_test.go), [zerolog](../adapters/zerolog/example_test.go) and [logrus](../adapters/logrus/example_test.go) Examples show complete setup and their actual JSON output.

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

Each adapter is its own module with a tag of the form `adapters/<name>/vX.Y.Z`, where `<name>` is `zap`, `zerolog`, `logrus`, `grpc`, `otel` or `sentry`, and requires the matching root release. The first published gRPC, OpenTelemetry and Sentry adapter versions are v0.5.0. The local replace directives are used only for development and CI; downstream builds ignore them.

## Shared JSON policy

The adapters use the same `Scanner.MaskJSON` engine as structured slog Any values. It masks decoded string leaves and object keys, preserves clean numeric lexemes without float64 conversion, and replaces the entire value of a sensitive key. `WithSensitiveKeys` therefore covers third-party structs, maps and HTTP headers after their logger encodes them, including custom marshaler output. See [the logging model and limits](logging.md) and [tag migration](values.md). Embargo's root module still has zero requirements; logger SDKs and comparison libraries stay in optional/test modules.

## Table explanations

<a id="table-explanation-1"></a>

Fits zapcore.NewCore with a JSON encoder and inspects the actual representation of every field type; Sync validates buffered output and delegates to the sink.

<a id="table-explanation-2"></a>

A Hook cannot remove fields already encoded in an Event. The writer buffers split JSON records and Close rejects an incomplete record without closing the caller-owned sink.

<a id="table-explanation-3"></a>

Wraps JSONFormatter after it formats the Entry, without modifying caller-owned fields or trusting a second serialization of an arbitrary value.


## Service and telemetry hooks

The HTTP hook lives in the root module and uses only the standard library. gRPC, OpenTelemetry and Sentry are separate Go modules, with declared root dependency checks that run both with and without local replacements. Install only the module the application uses. Constructor dependencies are required; nil and typed-nil dependencies are rejected. Each linked Example runs as a test, and the integration tests use the actual SDK or net/http server.

| Boundary | Constructor | Runnable Example | Integration test |
|---|---|---|---|
| HTTP access logs | NewHTTPHandler | [request and status](../example_test.go) | [httptest server and client](../http_handler_test.go) |
| gRPC unary access logs | NewUnaryServerInterceptor | [unary status and masked metadata](../adapters/grpc/example_test.go) | [health RPC over bufconn](../adapters/grpc/adapter_test.go) |
| gRPC stream access logs | NewStreamServerInterceptor | [stream failure record](../adapters/grpc/example_test.go) | [real Health Watch stream](../adapters/grpc/adapter_test.go) |
| OpenTelemetry log export | NewLogExporter | [masked log body](../adapters/otel/example_test.go) | [LoggerProvider and exporter](../adapters/otel/values_test.go) |
| OpenTelemetry span export | NewSpanExporter | [email span attribute](../adapters/otel/example_test.go) | [TracerProvider and exporter](../adapters/otel/values_test.go) |
| Sentry error events | NewBeforeSend | [message and context](../adapters/sentry/example_test.go) | [Client.CaptureEvent](../adapters/sentry/adapter_test.go) |

NewHTTPHandler always hides Authorization, Cookie and Set-Cookie in its access record. Additional headers and parsed query keys use the scanner's WithSensitiveKeys policy. It checks redirect Location values as URLs, including their parsed query keys, and scans other header values. It preserves request inputs, response status, body and wire headers; it is an access-log boundary, so a redirect sent to a browser is not sanitized by this middleware. Bodies are not recorded. The writer supports ResponseController, Flush, Hijack and Push; unsupported operations return the underlying error. A final header snapshot prevents later header-map changes from rewriting the logged response.

The gRPC server interceptors record incoming metadata, the method, final status code and error text. They preserve the returned error, including its status details, and never buffer request or response messages. Outgoing headers and trailers are not logged. Install them with grpc.UnaryInterceptor and grpc.StreamInterceptor; client logging and additional interceptors remain separate boundaries.

The OpenTelemetry exporter wrappers mask copied bodies, attributes, span names, events, links and status descriptions. Byte values are checked as text and retain their byte type; an already-base64-encoded secret is still subject to the encoding limit. Clean scalar types remain intact. Log resource and scope fields are immutable through the SDK record API: a batch requiring changes there is rejected in full. Spans instead expose copied resource and scope values. TraceState is omitted from span, parent and link contexts, since vendor values can carry arbitrary secrets. IDs, trace flags, times and counters remain intact. Export errors are fixed messages, with no partially forwarded batch after a masking failure. Lifecycle calls delegate to the supplied exporter. Log attribute updates preserve DroppedAttributes; a required key rename after earlier drops, or an update in duplicate-key mode that cannot preserve counters, rejects the batch. Masked-key collisions are rebuilt only from sanitized values and never restore an original value.

Sentry BeforeSend masks the serialized error-event fields and reconstructs a fresh event, keeping the original event unchanged. Attachments are omitted. Dynamic sampling context is masked alongside event content, then restored through a fresh SDK scope; clean sampling fields survive, and no private serialization cache is copied. Trace context in serialized fields remains subject to the masking policy. The helper is for ClientOptions.BeforeSend, not the separate BeforeSendTransaction, BeforeSendLog or BeforeSendMetric callbacks. A serialization or scanner failure returns nil, asking Sentry to drop the event. Downstream envelope additions and independently configured uploads need their own boundary.

Logrus uses Entry.Context when present, with cancellation checks before calling the formatter and between scanner calls. Zap WriteSyncer and zerolog Writer receive bytes without a context, so they have no cancellation source. HTTP and gRPC access logging, both OTel exporters and Sentry BeforeSend stop scanning on cancellation, including between detectors and scalar values. Service responses remain unchanged; canceled telemetry batches return a fixed error and Sentry drops canceled events. Sentry uses EventHint.Context, then EventHint.Request.Context when the former is absent; a missing hint has no cancellation source. Scanner.MaskJSONContext exposes the same cancellation boundary for other request-scoped JSON work. An already running detector or user marshaler cannot be interrupted.

## Production leak scenarios

| Scenario | Checked output | Expected result | Executable evidence |
|---|---|---|---|
| HTTP auth, cookies, custom header and query | Access record from a real request | Opaque values hidden; public field and status retained | TestHTTPHandlerMasksLogsAndPreservesExchange |
| Redirect containing a custom query secret | Logged Location | Hidden in log; original Location reaches the client | TestHTTPHandlerMasksLogsAndPreservesExchange |
| Unary RPC denied with a password in its error | gRPC access record | Error text and metadata masked; client code preserved | TestInterceptorsWithRealGRPC |
| Streaming RPC fails after starting | Final stream access record | One masked record; client receives original status | TestInterceptorsWithRealGRPC |
| OTel body, secret-key attribute and string slice | Exported log record | Text hidden; count stays an integer; input unchanged | TestExportersThroughRealProviders |
| Span resource, scope, link and error description | Exported ReadOnlySpan | All recorded text paths masked | TestSpanResourceScopeLinksAndStatusAreMasked |
| Log resource contains an opaque password | Export batch | Nothing forwarded | TestSensitiveResourceSuppressesLogBatch |
| Sentry request, context and breadcrumb contain secrets | Event delivered by the SDK | Serialized values hidden; public count retained | TestBeforeSendThroughSentryClient |
| Vendor TraceState contains email or an opaque session | Span, parent and link contexts | TraceState omitted; IDs and flags retained | TestSpanContextsOmitTraceStateWithoutChangingIdentity |
| Sentry sampling context contains a customer email | SDK envelope sampling context | Email masked; public sampling fields retained | TestClientPreservesAndMasksDynamicSamplingContext |

The [comparison matrix](comparison.md#service-leak-scenarios) measures older application-emission paths. These rows cover the added hooks and distinguish access logs from service wire output. Allocation gates and the scheduled five-size matrix include each new hook; the [threat model](threat-model.md) records what those measurements establish.

[Support maintenance](https://github.com/sponsors/nao1215).
