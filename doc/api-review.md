# API review: rounds 11 and 12

The twelve consumer-facing identifiers added in those rounds have distinct callers. None needs a second option type or a new wrapper. The changes below affect behavior; signatures stay compatible, apart from parameter names recorded by the API golden.

| Identifier | Decision | Use case and boundary |
|---|---|---|
| `WithSensitiveKeys` | Keep | Select application field names for slog, JSON and adapters; the same rule also recognizes text assignments. It replaces the key set, just as WithKinds replaces the detector set. |
| `(*Scanner).MaskJSON` | Keep | Sanitize an audit export or HTTP JSON body before sending it; a logger handler cannot cover those outputs. |
| `(*Input[T]).Scan` | Keep | Receive a database text column through `rows.Scan(&input)` and publish its Secret snapshot after loading. |
| `KindCredential` | Keep | Find a password in a DSN, assignment or authorization header even when the value has no recognizable format. |
| `KindServiceToken` | Keep | Recognize provider-prefixed credentials in free text without requiring a sensitive field name. |
| `KindHighEntropy` | Change selection | Inspect unlabelled random-looking tokens when explicitly requested by WithAll or WithKinds; NewScanner and its zero value omit it. Confidence remains 0.3. |
| `embargotest.Guard` | Keep | Supervise a whole package from TestMain, including its existing stdout, stderr and default logger. Recorder.Run instead names one isolated child helper. Both share Recorder options. |
| `embargotest.CheckValue` | Extend checks | Verify an application-owned secret type across encoders and formatters; now also test fmt inside an unexported field. |
| `(*Recorder).Setenv` | Keep | Inject the configured canary into an environment-based credential loader and delegate restoration to testing.TB. |
| `(*Recorder).File` | Keep | Supply a credential-file path with private file permissions and test-owned cleanup. Reader cannot exercise a path-based loader. |
| `(*Recorder).Header` | Keep | Create independent request-header input to test accidental forwarding or reflection. |
| `(*Recorder).Reader` | Keep | Feed the configured canary into request bodies or config parsers accepting io.Reader, without mutable sharing with the Recorder. |

No consumer-facing identifier was removed or merged: each has a working scenario in [the injection tests](../embargotest/inject_test.go), [SDK tests](../tests/compatibility_integration_test.go), [database tests](../input_sql_test.go), [JSON tests](../json_test.go) or [value checks](../embargotest/value_test.go). An application can always construct a header or reader from Canary itself; these methods keep fixture input tied to the Recorder's configured canary and lifecycle. They do not add alternative scanning or masking contracts.

Internal exports added in round 12 are `detect.Credential` with `MatchKey`, `detect.ServiceToken`, `detect.HighEntropy`, each type's `Name`, `Hints` and `Scan`, plus `NormalizeCredentialKey` and `SensitiveCredentialKey`. Scanner construction needs the three detector implementations; the methods satisfy the private Detector interface, and MatchKey connects the scanner's key policy. The two key functions keep assignment parsing and structured masking consistent. Go's internal-package rule prevents consumers outside this module tree from importing them. They are retained as package boundaries, not advertised as application APIs. Round 11 also added internal `output.JSON`, which shares structural masking between the root package and optional adapters; it remains exported only across that internal boundary. `maskedJSON.MarshalJSON` passes already-masked JSON to an encoder, `maskedJSON.String` supplies compact JSON to text handlers, and `guardStream.Write` captures a child output stream under the shared byte cap. Their receiver types are private, so they add no construction API. Round 12 also added the test-only `domain.Password` example with `String`, `GoString`, `Format`, `LogValue`, `MarshalJSON`, `MarshalText` and `MarshalXML`; each demonstrates the corresponding standard formatter boundary in values.md. Its new round 13 `NewPassword` constructor stores an unexported pointer so fmt cannot unwrap an unexported string field.

[Migration notes](migration.md), [API signature golden](../tests/contracts/testdata/embargo.golden), [embargotest signature golden](../tests/contracts/testdata/embargotest.golden).
