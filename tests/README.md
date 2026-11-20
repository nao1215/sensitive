# Test-only tools

All modules require Go 1.26.11. The root library remains dependency-free; external test tools and compatibility SDKs stay in this module. The optional logger adapters each have their own module. This test module uses rapid v1.3.0 for generation and automatic shrinking; `golang.org/x/crypto/sha3` supplies an independent Keccak oracle for EIP-55.

Run `go test ./... -rapid.checks=100` here, or increase `-rapid.checks` for exploration. On failure rapid prints a replay seed and stores a minimized case under `testdata/rapid/`; promote useful failures to named regression tests in the root. The local sanity check deliberately asserted that every integer in [0,100000] was below 7 and shrank to 7; that failing test is not committed.

Generators construct check digits and encodings independently: supported PAN brand lengths with Luhn, all 89 SWIFT registry IBAN country structures with big.Int MOD97, My Number MOD11, ABA weighted MOD10, formatted sort codes, BICs, EIP-55, Bitcoin Base58Check and BIP173/350 witness addresses, AWS/GitHub/Slack/Google token shapes, JWT segments, and PEM header kinds. Every generated component is a rapid draw; finite specification domains remain bounded, while contexts, token bodies, payloads, and reader placements vary. These are syntax and checksum tests, not evidence that generated identifiers are assigned or credentials authenticate.

Each family checks detection, exact raw bytes and offsets, separator-context invariance, Scan/ScanString/ScanLines equivalence, Mask idempotence, and last-four replacement through MaskFunc. Reader chunk sizes vary and placements cover 512-byte, 4-KiB, and 64-KiB boundaries. ScanLines equivalence uses one line because its offsets are line-relative. Digit strings that fail the PAN Luhn check are not findings; uniform-case Ethereum addresses are valid without EIP-55. Zero sort codes, unsupported ABA prefixes, unsupported Bitcoin networks and witness forms are outside the positive domain. PEM detection concerns headers, not key parsing; JWT detection does not verify signatures or payload JSON.

The root retains specification vectors, finite generated examples, golden logs, fuzz oracles, and regression tests. `testdata/recall.json` in the root contains two positive and two look-alike negative synthetic examples for each of 23 detectors; its test fails on any lost positive or new false positive. This small balanced corpus is a regression measurement, not an estimate of production prevalence or universal precision.

For comparable mutation measurements, run `GOMAXPROCS=4 make mutation` from the root of an isolated snapshot. Use gremlins v0.6.0 without `--test-cpu`: that release passes its value as a single malformed Go flag, which can falsely label mutants killed. Confirm the unmutated snapshot passes before measuring. This measures all root-module packages with their root-module tests, not rapid or SDK acceptance in the nested module; report that scope with the numbers. The byte alphabet, context window, date-ambiguity, and checksum regression tests target surviving mutants. Coverage CI separately instruments root packages from both modules and merges source blocks before octocov, so each statement contributes once.

Real logger/SDK acceptance, child-process goleak checks, API goldens and go/doc Example checks run here. The accuracy tests score the expanded synthetic corpus, including reviewed misses; Python checks connect those scores to the charts. Benchmark documentation tests compare recorded medians with every raw sample. Regeneration commands are in [doc/testing.md](../doc/testing.md).

## Tested outputs

Each link opens the test that checks the output.

<!-- tested-outputs:start -->
| Output | Actual output (excerpt for SDKs) |
|---|---|
| [fmt](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L150-L150) | `embargo.Secret[string]([REDACTED])` |
| [slog TextHandler](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L151-L154) | `level=INFO msg=event token=[REDACTED] nested.again=[REDACTED]` |
| [slog JSONHandler](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L155-L158) | `{"level":"INFO","msg":"event","token":"[REDACTED]","nested":{"again":"[REDACTED]"}}` |
| [encoding/json](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L159-L159) | `"[REDACTED]"` |
| [encoding/xml](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L160-L165) | `<record><token>[REDACTED]</token></record>` |
| [text/template](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L166-L172) | `[REDACTED]` |
| [zap JSON core](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L173-L179) | `{"level":"info","msg":"event","token":"[REDACTED]"}` |
| [zerolog JSON](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L180-L184) | `{"level":"info","token":"[REDACTED]","message":"event"}` |
| [logrus JSON](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L185-L191) | `{"level":"info","msg":"event","token":"[REDACTED]"}` |
| [OTel SDK](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L990-L1078) | `{"Key":"key","Value":{"Type":"STRING","Value":"[REDACTED]"}}` |
| [Sentry](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L652-L737) | `"signing":{"key":"[REDACTED]"}` |
| [HTTP](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L232-L254) | `[REDACTED]` |
| [Child panic](https://github.com/nao1215/embargo/blob/main/tests/integrations_test.go#L256-L266) | `panic: [REDACTED]` |
<!-- tested-outputs:end -->

Contributions and additional synthetic edge cases are welcome; please [sponsor maintenance](https://github.com/sponsors/nao1215).
