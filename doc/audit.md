# Measure the policy on your logs

Run the audit against a local application log before choosing scanner kinds. It counts findings, not confirmed secrets or false positives. A person must classify matched offsets against the source log and label a separate sample of missed values to estimate precision and recall. The public corpus and test count cannot supply those labels for your application.

## Run the released command

The command is part of the root module, which retains zero dependencies. The audit imports only embargo and the Go standard library and sends no log data anywhere.

```sh
go run github.com/nao1215/embargo/cmd/embargo-audit@v0.8.1 < app.log
go run github.com/nao1215/embargo/cmd/embargo-audit@v0.8.1 --all < app.log
go run github.com/nao1215/embargo/cmd/embargo-audit@v0.8.1 --kinds pan,credential --min-confidence 0.7 < app.log
```

The default is NewScanner's 25 kinds at minimum confidence 0. --all includes the national identifiers and entropy heuristic. --kinds replaces the selection; combining it with --all is rejected. --samples bounds locations per kind (default 3, range 0–20); counts still cover the complete input. Lines must be shorter than 4 MiB; read failures and oversized lines exit nonzero without a partial report.

For a log containing `card=4111111111111111`, a pan finding has start 5, end 21, line 1, column 5 and value `[REDACTED]`. Start/end are zero-based byte offsets in the original input, end-exclusive; line is one-based and column is a zero-based byte offset in that line. UTF-8 and CRLF offsets are tested. Multiple overlapping kinds can count the same bytes. Only matched spans are represented, with their values replaced; neither matched values nor surrounding log text are printed.

Each Kind includes a drop_option explaining how to omit it from WithKinds. Excluding a Kind also excludes real secrets of that kind. No per-Kind confidence option exists. This tool scans each raw line independently, so it does not apply MaskJSON's sensitive-key subtree policy or reassemble records and encoded values. Audit JSON masking separately through the handler or MaskJSON used by the application.

## Compare settings on the same input

`--compare` reports before/after counts and gained/lost findings, identified by kind and exact byte span. Both scanners see the same line before it is discarded. Samples stay masked, counts are complete, and incomplete input produces no report. The second setting defaults to NewScanner; use `--compare-kinds`, `--compare-all` and `--compare-min-confidence` to change it. These flags require `--compare`.

```sh
go run github.com/nao1215/embargo/cmd/embargo-audit@v0.8.1 --compare --compare-min-confidence 0.7 < app.log
go run github.com/nao1215/embargo/cmd/embargo-audit@v0.8.1 --compare --kinds pan,email --compare-kinds pan,credential < app.log
```

The gained/lost lists measure the effect of a selection, not whether that choice is correct for the application. Inspect the masked locations against your local source and retain application leak tests.

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
