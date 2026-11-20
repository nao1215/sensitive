# Mask and measure logs from the command line

The embargo command is part of the root module, which retains zero dependencies. It imports only embargo and the Go standard library and sends no log data anywhere.

## Mask a log

By default the command is a filter: it reads the named files in order, or stdin, and writes every line masked to stdout.

```sh
go install github.com/nao1215/embargo/cmd/embargo@v0.20.0
kubectl logs deploy/api | embargo > masked.log
embargo --kinds pan,credential app.log
```

[Releases](https://github.com/nao1215/embargo/releases) also carry archives for Linux, macOS and Windows on amd64 and arm64, plus deb, rpm and apk packages. `checksums.txt` is signed keylessly with cosign, every archive has an SBOM, and the SLSA provenance verifies with `slsa-verifier verify-artifact --provenance-path multiple.intoto.jsonl --source-uri github.com/nao1215/embargo --source-tag <tag> <archive>`.

A line that holds one JSON object or array goes through MaskJSON, so keys, types, nesting and the sensitive-key rule are kept and the line is written compact; any other line, and JSON that MaskJSON rejects (invalid or over 1 MiB), is masked as text. Line endings, including CRLF and a missing final newline, are kept. Output is flushed whenever no more input is buffered, so `tail -f app.log | embargo` shows each line as it arrives. A read failure or a line over 4 MiB stops the output before that line and exits nonzero with a message that names only the line number. `--kinds` takes `all` or a comma-separated list, `--min-confidence` a number from 0 to 1; option errors name the flag and its allowed values and never repeat what was passed. Flags come before the files, a file named `-` reads stdin in its place, and `--` ends the flags so a file name may start with a hyphen. A UTF-8 byte order mark is kept and does not hide the JSON line after it. An input that starts with a UTF-16 byte order mark, which Windows PowerShell 5 writes for `>`, stops with an error instead of passing through unmasked.

gzip and bzip2 input, including rotated logs such as `app.log.1.gz`, is decompressed; zstd, xz, zip, 7z and lz4 input stops with an error, since no detector reads compressed bytes. Lines are scanned on every CPU in batches and written in input order.

A value whose key is on an earlier line is masked when its key decides it: the value after `"token":` in pretty-printed JSON, everything in an array or object under a sensitive key, the lines of a YAML block scalar (`password: |`) or list under a sensitive key, and a CEF custom field such as `cs1=` whose `cs1Label=` names a sensitive key. A nested YAML mapping is decided by its own keys.

`--input csv` and `--input tsv` read the first line as column names, which work as keys for every field below them, as a JSON key does: a `password` or `cvv` column is masked although its values look like any text. A quoted field may hold the delimiter, doubled quotes and line breaks, and a line equal to the header, as when files are concatenated, is a header again. Files that all end in `.csv` or `.tsv`, optionally followed by `.gz` or `.bz2`, are read this way by default; `--input lines` turns it off.

## Run a command

`embargo run COMMAND [arg ...]` starts the command with embargo's stdin, masks its stdout onto stdout and its stderr onto stderr, and exits with the command's status. Flags go before `run`; everything after it belongs to the command.

```sh
embargo run sh app.sh >> app.log
embargo --kinds all run sh app.sh
```

A command ended by a signal exits with 128 plus the signal number, as in a shell. SIGTERM and SIGHUP sent to embargo are passed to the command, and embargo keeps masking until the command's output ends. Ctrl-C reaches the command from the terminal directly. A child process that keeps the output open after the command exits keeps embargo running, as it would keep a shell pipe open.

## Measure the policy

Run `--format json` against a local application log before choosing scanner kinds. It counts findings, not confirmed secrets or false positives. A person must classify matched offsets against the source log and label a separate sample of missed values to estimate precision and recall. The public corpus and test count cannot supply those labels for your application.

```sh
embargo --format json < app.log
embargo --format json --kinds all app.log
embargo --format json --kinds pan,credential --min-confidence 0.7 app.log
```

The default is NewScanner's 19 kinds at minimum confidence 0. `--kinds all` adds one country's formats and the entropy heuristic; a list replaces the selection. `--samples` bounds locations per kind (default 3, range 0–20) and works only with `--format json`; counts still cover the complete input. Every format reads lines exactly as the filter does: a line may hold up to 4 MiB, and a read failure or a longer line exits nonzero with a message naming the line. `--format json` then writes no partial report; text and jsonl stop before that line.

For a log containing `card=4111111111111111`, a pan finding has start 5, end 21, line 1 and column 5. Start/end are zero-based byte offsets in the original input, end-exclusive; line is one-based and column is a zero-based byte offset in that line. UTF-8 and CRLF offsets are tested. Multiple overlapping kinds can count the same bytes. Only matched spans are represented; neither matched values nor surrounding log text are printed.

Each Kind includes a drop_option saying how to leave it out with `--kinds`. Excluding a Kind also excludes real secrets of that kind. No per-Kind confidence option exists. The report scans each raw line independently, so unlike the filter it does not apply MaskJSON's sensitive-key subtree policy or reassemble records and encoded values. Audit JSON masking separately through the handler or MaskJSON used by the application.

## List every finding and gate CI

`--format jsonl` prints one JSON object per finding as each line is read, with its kind, byte offsets, line and column, and never the matched value. Unlike `--format json` it has no sample limit, so a script or an LLM agent can visit every location. A clean log prints nothing, so a CI step can fail on any output:

```sh
embargo --format jsonl app.log
out=$(embargo --format jsonl app.log) && test -z "$out"
```

The exit status says whether embargo ran, not whether it found something:

| Status | Meaning |
|---|---|
| 0 | the input was read in full, findings or not |
| 1 | an input, output or masking error |
| 2 | invalid flags or operands |
| 126, 127 | `run` could not start the command, or did not find it |
| 141 | the reader closed the output, as `head` does; nothing is printed |
| other | `run` passes on the command's status |

The CI line above fails on both a finding and an error. `! embargo --format jsonl app.log | grep -q .` would pass when embargo cannot read the file, because the error prints nothing.

## Compare settings on the same input

Run `--format json` once per setting on the same file and diff the two reports. Counts are complete and samples stay masked, so the diff shows which kinds a selection or threshold gains or loses without printing log text.

```sh
embargo --format json --kinds pan,email app.log > before.json
embargo --format json --kinds pan,credential --min-confidence 0.7 app.log > after.json
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

The default scanner already retains this request_id because its context filter excludes the candidate, but it masks the numeric order_id. This is a policy choice with a measured cost: an actual card mislabeled order_id is also skipped, because the business label lowers its confidence to 0.4. With these two kinds the threshold drops only business-labeled PAN candidates; with more kinds selected it drops every finding below 0.7, such as bank-account candidates. Selecting only PAN and Credential omits email, addresses and provider tokens without credential context; add the required kinds explicitly, for example KindGitHubToken, KindServiceToken, KindAWSKey or KindJWT. Keep threshold 0 when that recall loss is unacceptable, and use nonnumeric diagnostic IDs instead.

The default key list already leaves order_id and request_id out; adding them to WithSensitiveKeys would remove their entire values regardless of detector thresholds. WithSensitiveKeys adds to the key list, WithoutDefaultSensitiveKeys drops the defaults, and both affect raw credential assignments as well as structured masking. It is not an exclusion list for selected paths. There is no per-field exemption that preserves a card-shaped ID solely by field path while detecting the same mislabeled card as a secret. There is also no separate minimum confidence per Kind. These limits are part of the current scanner API.

## Check both directions

Inject distinctive fake cards and credentials into real error, HTTP and logger paths, then require their absence. Also assert the exact order ID, request ID, status and message needed to diagnose an incident, for example with Recorder.ExpectJSON. A test that accepts a fully redacted event can hide an operational failure. Review unmatched lines too: absence of findings is not measured recall. Keep a small application-owned labeled fixture set and rerun it when fields, logging libraries or scanner options change.

[Runnable leak cases](cases.md), [output-check independence](testing-output.md), [measured public-log false positives](real-logs.md).

[Support maintenance](https://github.com/sponsors/nao1215).
