# Mask and measure logs from the command line

The embargo command is part of the root module, which retains zero dependencies. It imports only embargo and the Go standard library and sends no log data anywhere.

## Mask a log

By default the command is a filter: it reads the named files in order, or stdin, and writes every line masked to stdout.

```sh
go install github.com/nao1215/embargo/cmd/embargo@v0.13.0
kubectl logs deploy/api | embargo > masked.log
embargo --kinds pan,credential app.log
```

[Releases](https://github.com/nao1215/embargo/releases) also carry archives for Linux, macOS and Windows on amd64 and arm64, plus deb, rpm and apk packages. `checksums.txt` is signed keylessly with cosign, every archive has an SBOM, and the SLSA provenance verifies with `slsa-verifier verify-artifact --provenance-path multiple.intoto.jsonl --source-uri github.com/nao1215/embargo --source-tag <tag> <archive>`.

A line that holds one JSON object or array goes through MaskJSON, so keys, types, nesting and the sensitive-key rule are kept and the line is written compact; any other line, and JSON that MaskJSON rejects (invalid or over 1 MiB), is masked as text. Line endings, including CRLF and a missing final newline, are kept. Output is flushed whenever no more input is buffered, so `tail -f app.log | embargo` shows each line as it arrives. A read failure or a line over 4 MiB stops the output before that line and exits nonzero with a message that names only the line number. `--kinds` takes `all` or a comma-separated list, `--min-confidence` a number from 0 to 1; option errors name the flag and its allowed values and never repeat what was passed. Flags come before the files, a file named `-` reads stdin in its place, and `--` ends the flags so a file name may start with a hyphen.

## Measure the policy

Run `--report` against a local application log before choosing scanner kinds. It counts findings, not confirmed secrets or false positives. A person must classify matched offsets against the source log and label a separate sample of missed values to estimate precision and recall. The public corpus and test count cannot supply those labels for your application.

```sh
embargo --report < app.log
embargo --report --kinds all app.log
embargo --report --kinds pan,credential --min-confidence 0.7 app.log
```

The default is NewScanner's 26 kinds at minimum confidence 0. `--kinds all` includes the national identifiers and entropy heuristic; a list replaces the selection. `--samples` bounds locations per kind (default 3, range 0–20) and requires `--report`; counts still cover the complete input. The report reads lines exactly as the filter does: a line may hold up to 4 MiB, and a read failure or a longer line exits nonzero with a message naming the line and without a partial report.

For a log containing `card=4111111111111111`, a pan finding has start 5, end 21, line 1 and column 5. Start/end are zero-based byte offsets in the original input, end-exclusive; line is one-based and column is a zero-based byte offset in that line. UTF-8 and CRLF offsets are tested. Multiple overlapping kinds can count the same bytes. Only matched spans are represented; neither matched values nor surrounding log text are printed.

Each Kind includes a drop_option saying how to leave it out with `--kinds`. Excluding a Kind also excludes real secrets of that kind. No per-Kind confidence option exists. The report scans each raw line independently, so unlike the filter it does not apply MaskJSON's sensitive-key subtree policy or reassemble records and encoded values. Audit JSON masking separately through the handler or MaskJSON used by the application.

## Compare settings on the same input

Run `--report` once per setting on the same file and diff the two reports. Counts are complete and samples stay masked, so the diff shows which kinds a selection or threshold gains or loses without printing log text.

```sh
embargo --report --kinds pan,email app.log > before.json
embargo --report --kinds pan,credential --min-confidence 0.7 app.log > after.json
diff before.json after.json
```

The difference measures the effect of a selection, not whether that choice is correct for the application. Inspect the masked locations against your local source and retain application leak tests.

## Keep diagnostic identifiers

Start with the kinds your service handles. For a payment service whose relevant credentials follow the Credential grammar, this recipe keeps a BIC-shaped request ID and a card-shaped order ID while masking an actual card field and Authorization value:

```go
scanner := embargo.NewScanner(
    embargo.WithKinds(embargo.KindPAN, embargo.KindCredential),
    embargo.WithMinConfidence(0.7),
)
```

The [executable recipe](../tests/cases_test.go) checks this JSON output, including the retained values:

```json
{"order_id":"4111111111111111","request_id":"DEUTDEFF","card":"[REDACTED]","authorization":"[REDACTED]"}
```

The default scanner already retains this request_id because its context filter excludes the candidate, but it masks the numeric order_id. This is a policy choice with a measured cost: an actual card mislabeled order_id is also skipped, because the business label lowers its confidence to 0.4. The global 0.7 threshold additionally drops checksum-failed PAN candidates and low-confidence kinds. Selecting only PAN and Credential omits email, addresses and provider tokens without credential context; add the required kinds explicitly, for example KindGitHubToken, KindServiceToken, KindAWSKey or KindJWT. Keep threshold 0 when that recall loss is unacceptable, and use nonnumeric diagnostic IDs instead.

The default key list already leaves order_id and request_id out; adding them to WithSensitiveKeys would remove their entire values regardless of detector thresholds. WithSensitiveKeys replaces the key list and affects raw credential assignments as well as structured masking. It is not an exclusion list for selected paths. There is no per-field exemption that preserves a card-shaped ID solely by field path while detecting the same mislabeled card as a secret. There is also no separate minimum confidence per Kind. These limits are part of the current scanner API.

## Check both directions

Inject distinctive fake cards and credentials into real error, HTTP and logger paths, then require their absence. Also assert the exact order ID, request ID, status and message needed to diagnose an incident, for example with Recorder.ExpectJSON. A test that accepts a fully redacted event can hide an operational failure. Review unmatched lines too: absence of findings is not measured recall. Keep a small application-owned labeled fixture set and rerun it when fields, logging libraries or scanner options change.

[Runnable leak cases](cases.md), [output-check independence](testing-output.md), [measured public-log false positives](real-logs.md).

[Support maintenance](https://github.com/sponsors/nao1215).
