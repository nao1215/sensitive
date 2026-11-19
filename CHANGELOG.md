# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Masking is faster with the same output: slog events take 5% to 16% less time than in v0.18.0, MaskJSON 11% less and Scan of plain log lines up to 23% less.

## [0.18.0] - 2026-11-20

### Changed

- Tests check the `Mask` guarantee that, for fixed valid findings, the output depends only on the bytes outside them. They run the real function on every combination of up to three ranges over texts of up to seven bytes, the exact spans a `MaskFunc` callback receives, and that findings on valid UTF-8 never split a character.
- The Lean reference proofs no longer model masking. That model replaced each byte with `*` and missed changes that made the marker return the value; the README row now reads "Checksum and offset-map errors". doc/testing.md has a Masking guarantee section listing what it covers and what it does not.
- The `Mask` and `MaskFunc` godoc states the guarantee: for valid findings, `Mask` output depends only on the bytes outside the spans, and a `MaskFunc` callback that returns part of the value discloses that part.
- slog, MaskJSON, the adapters and the HTTP hook now share one rule set for keys, key paths and name/value pairs.
- A slog record shares one 4 MiB scan budget.
- A test checks every value representation, key wrapping and sink against MaskJSON of `{"key":"secret"}`.
- The threshold table in doc/accuracy.md covers only the kinds `NewScanner` reports.
- Adapters are covered by the API goldens, the coverage gate and the mutation gate.
- The CI speed gate also measures MaskJSON and slog.
- Releases wait for the tagged commit's other checks to pass.
- CI runs the tests on GOARCH=386.

### Fixed

- slog groups and records with `name` and `value` attributes kept the value.
- A JSON name/value object with two `value` members kept the first.
- Short `[]byte` fields inside structs, maps and slices were written as unscanned base64.
- A panic in the downstream handler while writing the withheld diagnostic escaped the HTTP and gRPC hooks.
- doc/threat-model.md and doc/countries.md stated outdated facts.

### Detection changes

- Base64 text shorter than 20 bytes is now decoded and scanned.

### Removed

- doc/migration.md. The [v0.17.0 copy](https://github.com/nao1215/embargo/blob/v0.17.0/doc/migration.md) remains.

## [0.17.0] - 2026-11-19

### Added

- `KindPhone` detects international phone numbers written with `+` and an assigned country calling code, such as `+44 20 7946 0958`, `+1 (202) 555-0123` and `+919876543210`, so a scanner masks phone numbers from every country without one detector per country. It is on by default. Numbers without `+` follow one country's rules and stay with `KindJPPhone` and `KindUSPhone`.
- `WithMoreKinds` adds kinds to the selection made so far, so `NewScanner(embargo.WithMoreKinds(embargo.KindMyNumber, embargo.KindJPPhone))` keeps the default and adds Japan's formats. `WithKinds` and `WithAll` still replace the selection.

### Changed

- `NewScanner()` now runs 19 detectors instead of 26. The default keeps what the OWASP Logging Cheat Sheet and PCI DSS keep out of logs in formats used in every country: credentials and provider tokens, card and bank account data, email, IP and international phone numbers, and cryptocurrency addresses. `KindMyNumber`, `KindJPPhone`, `KindUSPhone`, `KindABARouting`, `KindUKSortCode` and `KindACHTrace` describe one country's formats and are opt-in like the national IDs; `KindSWIFTBIC` and `KindMerchantID` identify banks and merchants, not people, and are opt-in too. To keep the previous coverage, add `embargo.WithMoreKinds(embargo.KindMyNumber, embargo.KindJPPhone, embargo.KindUSPhone, embargo.KindABARouting, embargo.KindUKSortCode, embargo.KindACHTrace, embargo.KindSWIFTBIC, embargo.KindMerchantID)`. On the public logs, the default false-positive rate of the held-out web access log drops from 1,265.4 to 0 findings per GB.
- The README's detector table links each kind's runnable Example instead of repeating its rule; the rules stay in the godoc.

### Detection changes

- The default scanner no longer masks My Number, Japanese and North American phone numbers in their national formats, ABA routing numbers, UK sort codes, ACH trace numbers, SWIFT/BIC codes and merchant IDs. A Japanese or North American number written with `+81` or `+1` is still masked, now by `KindPhone`. Random 12-digit business identifiers that pass the My Number check digit, one in ten, are no longer masked by default.

### Removed

- `Secret.GoString` and `Input.GoString`. `Format` already wrote the `%#v` output, so `fmt.Sprintf("%#v", secret)` still prints `embargo.Secret[string]([REDACTED])` and an `Input` still prints `[REDACTED]`; neither type implements `fmt.GoStringer` any more.
- `embargotest.Recorder.File`. Write `r.Canary()` to a file with `os.WriteFile` when the code under test reads a secret from a path.

### Fixed

- The parallel table in doc/benchmarks.md showed no speed-up from 1 to 16 CPUs since 0.15.0, because the benchmarks ran pinned to one CPU; re-measured on 24 CPUs, 16 goroutines are 10.0 times faster than one through Scanner.Scan, 7.8 times through the slog handler and 4.6 times through the zap WriteSyncer. `make benchmark-doc` now refuses to run with fewer than 16 CPUs in its affinity. Speed comparisons in the README, doc/comparison.md, doc/benchmarks.md and earlier release notes now say how many times faster or slower, instead of a fraction of the other library's time.

## [0.16.1] - 2026-11-19

### Fixed

- KindServiceToken no longer leaves the first of two dot-joined provider tokens visible, as in `glpat-….glpat-…`: the routing suffix of a GitLab token stopped at the second token's prefix, the boundary check then rejected the first token, and only the second was masked. A routing part that runs into `-` or `_` now ends the suffix before its dot.

## [0.16.0] - 2026-11-19

### Added

- `WithMaskFunc` sets the replacement for detected spans in log records, MaskJSON output, the HTTP handler and the logger adapters, the same callback that `MaskFunc` takes for text, so a log line can keep the last four digits of a card as `card=****1111`. Values under sensitive keys, encoded text, numbers that a finding covers only in part and records withheld on failure still become `[REDACTED]`, and a replacement that contains the value falls back to `[REDACTED]`. Without the option, output is unchanged.

### Detection changes

- KindCredential reports a quoted value passed right after a quoted credential key in an argument or initializer list, such as `System.setProperty("db.password", "…")`, `put("api_key", "…")` and `Map.of("password", "…")`, and a value assigned to a quoted subscript such as `os.environ["DB_PASSWORD"] = "…"` or `ENV['SECRET_KEY'] = '…'`. An Authorization value keeps its scheme, as in other assignments.

### Changed

- The slog handler no longer allocates for the clean and flat comparison events: detectors append findings to reused storage, plain ASCII values skip the escape and separator passes, and slog Bool, Int64 and Uint64 values are formatted without allocating. A record with more than 16 attributes reuses its working slice. With the email and card rules, embargo is now 1.06 to 1.43 times faster than go-masker on all five comparison events (in 0.15.0 it ranged from 1.03 times slower on flat to 1.21 times faster), and the default scanner is 1.79 to 3.33 times faster than pii-shield (1.69 to 2.94 times in 0.15.0).

## [0.15.0] - 2026-11-19

No exported API changes: code that builds against v0.14.0 builds unchanged. Masked output changes are listed under Detection changes; Changed lists messages and other observable behavior.

### Detection changes

- MaskJSON, the slog handler and the logger adapters mask the value of an object that keeps a setting in separate name and value members, such as `{"name":"DB_PASSWORD","value":"hunter2"}` in Kubernetes env, ECS task definitions, SSM `GetParameters` responses (`Name` may be a path such as `/prod/db/password`) and CloudFormation `ParameterKey`/`ParameterValue`. The value is masked when the name, key, ParameterKey, ParameterName, OptionName or variable member is a sensitive key, in either member order: a string, or a whole object or array, which becomes `"[REDACTED]"` as under a sensitive key. Numeric values, as in metric samples, stay visible.
- The default sensitive keys add otp, pin, passcode, passphrase, session, session_id, session_token, JSESSIONID and PHPSESSID, and the suffix rule adds pwd, passcode, passphrase, otp and pass after another segment (DB_PASS). Bare pass and pwd count only as structured keys, because text such as `--- PASS: TestX`, `pass=12 fail=0` and `PWD=/srv` is public.
- KindMyNumber no longer reports a 12-digit value whose attached label names a record identifier: a word ending in id (accountId, recipientAccountId, user_id), account, user, customer, order, invoice, tracking and similar record words, number or no unless it follows my or individual, and Japanese labels containing 番号 or a business stem such as 注文. Random 12-digit IDs, including AWS account IDs, pass the check digit about one time in ten; on the accuracy corpus My Number precision rises from 81.8% to 100% with recall unchanged. My Number, mynumber, マイナンバー and 個人番号 labels keep the candidate.
- KindPAN no longer reports a 13-digit number that also passes the EAN-13 check digit, such as a JAN product code starting with 45 or 49; about one valid JAN code in ten used to be masked as a card at confidence 1.0. Card numbers written as four dot-separated groups of four digits are now recognized.
- KindABARouting and the opt-in country kinds (US SSN and ITIN, UK NINO and NHS, Aadhaar, India PAN, CPF, CNPJ, China resident ID, RRN and SIN) no longer report a value whose attached label names a record identifier, such as `user_id=657204589` or `order no 943 476 5919`; a label naming the number, such as routing, ssn, nhs or aadhaar, keeps it. The country kinds used to report such values at 0.4 under a business label such as order_id; on the country corpus their precision rises from 75% to 100% with recall unchanged. Under WithAll, 88% of random nine-digit user_id values used to be masked as a US SSN and about 9% of ten- and twelve-digit ones as NHS or Aadhaar numbers.
- KindPAN, KindJPPhone and KindUSPhone drop to 0.4 under any record label, the same words that rule out My Number, ABA and country candidates (user_id, customerID, account, 注文番号, 品番 and others), instead of only order, invoice, tracking, version, build, serial and shipment. They stay reported, because a card or phone number under such a field is still one; a label naming the number, such as card_id, credit card number, phone_id or 電話番号, keeps the full score.
- The opt-in KindUSSSN, KindUSITIN, KindCanadaSIN, KindUKNHS and KindIndiaAadhaar report a bare digit run such as `663271262` only after a label naming the number, such as ssn, itin, sin, social insurance number, nhs or aadhaar; separated forms such as `663-27-1262` need no label. SSN and ITIN have no check digit and the others pass about one random ID in ten, so on the public logs under WithAll, unlabeled Android event times, lock identifiers and BGL counters were about 20,500 SSN, 1,900 SIN and 2,300 NHS false positives per GB; only one hyphenated hostname fragment remains, as a SIN. The cost is recall on unlabeled values: on the country corpus, whose positives use neutral labels such as identity, these five kinds now find only the separated third, 33.3% recall from 100%.
- KindJPPhone recognizes the +81 international form, such as `+81-90-1234-5678`, `+819012345678` and `+81 (0)3-1234-5678`, and masks the opening parenthesis of a parenthesized area code such as `(03)1234-5678` instead of leaving `([REDACTED]`.
- KindEmail recognizes an address written with the full-width at sign ＠, with ASCII or full-width letters, such as `bob＠example.com` and `ｂｏｂ＠ｅｘａｍｐｌｅ．ｃｏｍ`.
- KindServiceToken recognizes Google OAuth access tokens (`ya29.`) and refresh tokens (`1//0`), Discord webhook URLs (reporting the ID and token path) and the key of a hosted Sentry DSN.
- KindCredential reports the value of a long option named by a sensitive key when it is a separate word (`--password hunter2`), the attached `-p` value of mysql and mariadb clients (`mysql -phunter2`) and the word after sshpass `-p`.
- KindIPAddr recognizes IPv4 addresses with octets zero-padded to three digits, such as `192.168.001.010`, and no longer reports a four-part version after a product name and slash, such as `agent/5.1.2.3` in a User-Agent; `ip/`, `host/`, `peer/` and similar address words keep the address.
- KindCredential ends a `;jsessionid=` value at the query string, so `?x=1` after it stays visible, and treats `auth_key`, `X-Auth-Key` and `master_key` as credential keys.

### Changed

- Structured values (MaskJSON, the slog handler and the logger adapters) are dispatched on the value. The field name selects only detectors whose hints are keywords, such as cvv or account number, and a repeated clean key reuses its selection from the key cache. A detector that reads the field name skips the `key: value` text when the value cannot hold its candidate: too few digits for a card, phone, My Number, ABA or sort code, or no word shaped like a SWIFT code. IBAN, sort codes and BTC need digits in the text. On the JSON slog comparison events, embargo with the default kinds is 1.69 to 2.94 times faster than pii-shield, where v0.14.0 ranged from 1.07 times slower to 1.64 times faster, and on the large50 event it is 2.70 times faster than masq, where v0.14.0 was 1.13 times slower. Masked output is unchanged.
- embargotest Check failures name the sinks and finding kinds, for example `sensitive data appeared in captured output: app.log (email)`. Captured bytes still never appear, and a sink name longer than 64 bytes, with other bytes than ASCII letters, digits and `_ . / : -`, or with a finding or the canary of its own is written as `a sink with an unprintable name`.
- `WithKinds` and the `embargo --kinds` flag name a misspelled kind and suggest the nearest built-in one, as in `unknown built-in kind "emial" (did you mean "email"?)`; other unknown values are still not repeated. The `embargo` command names a defined flag that lacks a value, lists the flags for an unknown one, and gives the position and cause of a file it cannot open (`input file 2 cannot be opened: no such file`) without its name.
- The JSON limit error reads `embargo: JSON size or nesting limit exceeded`, because nesting deeper than 64 levels returns it too.

### Fixed

- A `Secret` value no longer appears in printers that walk struct fields without calling String, such as go-spew and the failure diffs of testify `assert.Equal`. The value now lives in a closure, so reflection reaches only a function value; Secret stays comparable.
- The README access-log example and its runnable example name `KindIPAddr`, not the nonexistent `KindIPAddress`, and the kind-selection benchmark table prints whole nanoseconds.

## [0.14.0] - 2026-11-18

### Detection changes

- The SWIFT/BIC and UK sort code context keywords (swift, bic, wire, sort code, bacs and the others) ignore ASCII case only, like every other keyword detector. They used Unicode lowering, so a non-ASCII letter such as the Kelvin sign counted as k, and a lowered character with a different byte length shifted the label check after swift.
- Every built-in detector reads a backslash-u escape of an ASCII character (`\u0040` for `@`) as that character, as it already read one layer of percent escapes. Text that MaskJSON does not parse, such as a pretty-printed JSON document read line by line, a JSON string inside a text log line or an `embargo` input line over the 1 MiB MaskJSON limit, printed `alice\u0040example.com` unmasked. Escapes of non-ASCII characters and escapes after an escaped backslash stay literal.
- KindPAN no longer reports digits that fail the Luhn check. Every issued card satisfies it; the 0.6 candidates were order, request and trace IDs, Snowflake IDs and decimal span IDs that start like a card, about 28% of random 16-digit IDs and 27% of decimal 64-bit trace IDs. On the frozen accuracy corpus the critical tier keeps every true positive with no misses and drops false positives from 97 to 33; PAN precision rises from 60.1% to 81.6% with recall at 100%. A mistyped card number is no longer masked.
- KindHighEntropy skips values assigned to `continue` or a key ending in `cursor`, such as the Kubernetes list `continue` parameter, `next_cursor` and the GraphQL `endCursor`. These pagination cursors carry list state, not credentials; a Kubernetes audit log in the public evaluation showed one once escape decoding moved the boundary after it.
- MaskJSON, the slog handler, the HTTP handler and the logger adapters decode a string value of 20 bytes to 8 KiB that is padded standard base64 and scan the bytes when they are printable UTF-8 text, hiding the whole value on a finding. encoding/json, zap.Binary, zerolog, logrus and Sentry write a `[]byte` field in this form, so a token in a byte field of a struct, map or slice reached the output recoverable. Binary data and other base64 alphabets are not scanned; `Scanner.Scan` on plain text is unchanged.
### Added

- `WithoutDefaultSensitiveKeys()` drops the default sensitive key names and suffix rule, for a public field named token or an export that must hide exactly the keys it lists.

### Removed

- `embargotest.Recorder.Setenv`, `Header` and `Reader`. Each wrapped one standard call on the canary; use `t.Setenv(key, string(r.Canary()))`, `header.Set(name, string(r.Canary()))` and `bytes.NewReader(r.Canary())`.

### Changed

- `WithSensitiveKeys` adds names to the default key policy instead of replacing it, and repeated options add to each other. Passing your own key used to drop password, token and the suffix rule that matches names such as POSTGRES_PASSWORD, and copying the documented defaults could not bring the suffix rule back. Use the new `WithoutDefaultSensitiveKeys()` to drop the defaults; `WithSensitiveKeys()` with no names no longer disables the policy.
- The `embargo` command chooses its output with one flag, `--format text|json|jsonl`. `--report` is replaced by `--format json`, and `--samples` now requires it. The new `--format jsonl` prints one object per finding (kind, byte offsets, line and column, never the value) as each line is read, without a sample limit; a clean log prints nothing, so `out=$(embargo --format jsonl app.log) && test -z "$out"` gates CI without jq and also fails when the input cannot be read.
- `embargotest.WithLimits(maxBytes, timeout)` is split into `WithMaxBytes(n)` and `WithTimeout(d)`, so a test can raise one bound without restating the other default.
- A file named `-` reads stdin in its place, as in cat, so `embargo header.log - footer.log` works in a pipe.
- The `--format json` report no longer has the `value` field in each sample; it always held `[REDACTED]`. Each kind's `drop_option` now names the `--kinds` flag instead of the Go option.
- `embargo --help` describes each format, lists `--help` and the flag order, and names the default kinds as NewScanner's defaults.

### Fixed

- `embargo` rejects a flag placed after a file name instead of reading it as a file. `embargo a.log --kinds email` used to mask a.log with the default kinds and then fail on a file named `--kinds`; it now exits with `flags must come before the files`. `--` still ends the flags.
- embargotest finds the canary after one layer of JSON `\u` escapes and one layer of percent escapes are decoded from the output. A canary passed through `url.QueryEscape` or `url.PathEscape`, for example into a redirect `Location`, or written by an encoder that escapes every character, passed Check.
- `embargo` masks every line of a multi-line PEM or PGP private key block, as `Scanner.ScanLines` does. It scanned each line alone, so only the BEGIN line was masked and the key body and END line were printed; `--format json` and `--format jsonl` did not count them either. A block without its END line covers the rest of the input.
- `MaskJSONContext` returns a cancellation error that `errors.Is` matches with the context error, `context.Canceled` or `context.DeadlineExceeded`, keeping its fixed text. It used an internal type that callers could not classify.
- The report reads lines exactly as the filter does. A final line of exactly 4 MiB was accepted by the filter and rejected by the report, and the report error did not say which line; both now accept up to 4 MiB and name the line that stops them.

### Performance

- A zero `Scanner` shares one default policy built on first use. It built a new NewScanner policy on every call, about 1,400 allocations and 200 KiB for one clean line.
- WithKinds builds the list of known kinds once per call instead of once per kind passed.

## [0.13.0] - 2026-11-18

The public-log evaluation adds seven operations logs that LogHub lacks: Nginx and Apache access logs, a 92.8 MB Kubernetes API server audit log and three AWS CloudTrail files. Their development files exposed four false-positive classes, fixed below.

### Detection changes

- PAN, MyNumber, Japanese phone, country identifier and SWIFT/BIC detection skip groups inside a canonical 8-4-4-4-12 UUID. Kubernetes `auditID` and CloudTrail `eventID`/`requestID` values contain all-digit groups that pass identity-number checksums by chance, and hex groups such as `bccbca47` that look like lowercase BICs.
- `KindIPAddr` skips IPv4 addresses whose first octet is zero. That block is never a host address; the 0.0.0.0 listener was already skipped, and other members appeared as version strings such as `Debian APT-HTTP/1.3 (0.9.7.9)`.
- `KindCredential` leaves a canonical UUID under `clientToken` or `idempotencyToken` visible. CloudTrail records these EC2 request deduplication keys, which authenticate nothing; other token keys holding a UUID are still masked.
- `KindHighEntropy` (opt-in) skips lowercase Kubernetes generated names such as `my-vault-agent-injector-9d457c8b-5pqfx`, whose five-character suffix uses the Kubernetes random alphabet.
- `KindUSPhone` treats an opening parenthesis as its own boundary. `x(212) 555-0100` and a number glued to the previous one, as in `202-555-0108(212) 555-0118`, were left visible because a letter or digit came right before the parenthesis; the second number then appeared only after a second masking pass. A parenthesis after `/` or `+` still does not start a number.

### Performance

- The zap and zerolog writers mask a whole event outside their lock and only serialize the sink write, so goroutines that log at the same time mask in parallel. Before, every event went through one lock: on 16 CPUs a zap logger shared by 16 goroutines took as long per event as on one CPU. doc/benchmarks.md has a parallel table for the scanner, the slog handler and the zap writer. Output is byte-identical.
- The IP address, MyNumber and Japanese phone detectors no longer allocate on candidates that cannot match: a digit run with fewer than three dots or a hex run with fewer than two colons skips the address parse, and digit runs go into a stack buffer. A default-scanner pass over a short JSON log line went from 30 to 3 allocations, and a clean line from 21 to 0.

### Changed

- The README speed comparison times each library against an embargo configuration of similar detection breadth: masq, go-masker and ferret-scan (narrowed to its EMAIL and CREDIT_CARD checks) against embargo with email and card, and pii-shield, whose built-in detectors cannot be turned off, against embargo's default scanner. ferret-scan moves from v1.10.0 to v2.4.3, the newest release that builds on Go 1.26. doc/benchmarks.md adds a parallel table for a scanner, slog handler and zap logger shared by 1, 4 and 16 goroutines.

### Added

- doc/real-logs.md has a per-family table (system, web access, Kubernetes audit, cloud audit) with current FP/GB for WithAll and the default scanner.

## [0.12.0] - 2026-11-18

The default scanner now recognizes about 70 more provider credential layouts and more assignment syntax, measured against the true-positive examples of the gitleaks v8.30.0 rules: it masks 5930 of 6368 generated lines (4349 before) and 321 of 539 bare secrets (105 before). The eight pinned public log datasets produce exactly the same findings as before.

### Added

- `scripts/gitleaks_oracle.py --cache DIR` generates the gitleaks rule examples outside the repository and prints how many the default scanner masks; doc/credentials.md records the result and the layouts.

### Detection changes

- `KindServiceToken` recognizes provider layouts from DigitalOcean, Shopify, HashiCorp Vault and Terraform, Databricks, Doppler, Dynatrace, Postman, Pulumi, Sentry, Grafana, Hugging Face, New Relic, Twilio API keys, Microsoft Entra client secrets, Telegram bots, MaxMind, Mailchimp, Facebook, PlanetScale, Sourcegraph, 1Password, age, Alibaba Cloud, AWS Bedrock, more GitLab prefixes and others listed in doc/credentials.md, plus Slack workflow and trigger webhooks with or without a scheme and Microsoft Teams incoming webhooks. GitLab tokens now include dot-separated routing suffixes, and a prefix followed by one repeated byte, such as `glpat-xxxxxxxxxxxxxxxxxxxx`, is treated as a placeholder and left visible.
- `KindAWSKey` also recognizes ABIA and ACCA access-key IDs, and `KindSlackToken` recognizes `xoxe-` tokens.
- `KindCredential` accepts `::=`, `:::=`, `?=`, `+=`, `||=` and spaced `.=` operators, Go typed declarations (`var token string = "..."`), string type annotations (`token: String = "..."`), PHP `print_r` keys (`[api_token] => ...`), XML elements named by a credential key (`<wsse:Password>...</wsse:Password>`), curl `-u`/`--user` passwords, keys with a numeric suffix such as `api_token_2`, `credentials`, `creds` and joined `ACCESSKEY`, `SECRETKEY`, `APIKEY` or `PRIVATEKEY` segments.

### Performance

- Detector selection checks the byte after each possible hint start against the hints' second bytes before comparing whole hints, so the larger provider table does not slow clean input: the default scanner's clean workload is about 10% faster than 0.11.0 on the same machine and the dirty workload within 2%.

### Fixed

- A credential written with the Ruby, Perl or PHP hash arrow (`{"api_token" => "value"}`, the default Ruby `inspect` output) or a Make `::=` operator was not masked: only the `>` or `:` after the separator was replaced and the value stayed visible.

## [0.11.0] - 2026-11-18

The command-line tool is now `embargo`: by default it masks each line of files or stdin, keeping JSON lines' shape, and `embargo --report` replaces `embargo-audit`. Masking is faster with fewer allocations and unchanged output. The public library API only adds `KindUSPhone`, and the root module remains dependency-free. Upgrade every installed adapter to v0.11.0 after the adapter tags are published.

### Added

- `KindUSPhone` detects separated ten-digit North American numbers, `(NXX) NXX-XXXX`, `NXX-NXX-XXXX`, `NXX.NXX.XXXX` and `NXX NXX XXXX` with an optional `+1` or `1`, checked against the numbering plan. It runs by default, so NewScanner now selects 26 of 38 kinds; it found nothing on the eight pinned public log datasets. Unseparated digit runs are not matched.

### Detection changes

- The default scanner now masks separated North American phone numbers (`KindUSPhone`). Select kinds without it to keep them.
- Email no longer matches the userinfo of a URL (`scheme://user@host`, `scheme://user:password@host`), the same exclusion SCP-style Git remotes already had. With the default kinds, `postgres://app:s3cr3t@db.example/orders` now masks to `postgres://app:[REDACTED]@db.example/orders`: the credential rule still masks the password and the host stays readable, where the overlapping email span used to hide the host as well. Text in that position is read as a user name and host even when it looks like an address, so `https://alice@example.com/` is no longer reported as an email.

### Changed

- The `cmd/embargo-audit` command is replaced by `cmd/embargo` (`go install github.com/nao1215/embargo/cmd/embargo@latest`). `embargo [flags] [file ...]` writes every line masked: JSON object and array lines go through MaskJSON and are written compact, other lines are masked as text, line endings are kept and output is flushed whenever no more input is buffered, so it works behind `tail -f`. Migration: `embargo-audit` becomes `embargo --report`; `--all` becomes `--kinds all`; `--samples` now requires `--report`; the four `--compare` flags are removed, so diff two `--report` runs instead. Both modes read files as well as stdin. Releases now publish signed archives and deb, rpm and apk packages of the command with SBOMs, build attestations and SLSA provenance; `make build` builds it locally.

### Performance

- The slog handler and MaskJSON reuse scan buffers, add all attributes to a record at once, cache the masked spelling and key policy of up to 1024 clean keys and messages of at most 64 bytes per built-in scanner, skip re-validating encoding/json output and copy clean JSON string lexemes without decoding them. Card detection skips text with fewer than 13 digits, and the normalized view tests 32 bytes at a time for non-ASCII input, so clean ASCII text with a narrow kind selection scans about ten times faster. On the comparison events allocations fell from 14–169 to 2–18 per record; output is byte-identical on the full equivalence corpus.

### Fixed

- Numeric-looking JSON strings with trailing JSON whitespace no longer produce a false size-limit error during exact integer expansion. Original clean string bytes and the existing numeric-string masking policy are preserved; genuine expansion limits still fail closed.
- Scheduled fuzz failures on main maintain one issue with target, run and crasher artifact links, and the next successful main-branch run closes it.

## [0.10.0] - 2026-11-17

This minor release closes IP punctuation, authorization-list, encoded private-key and Go-value masking gaps, refines measured SWIFT/ABA log contexts, and improves safe input diagnostics. The public API and default minimum confidence of 0 are unchanged, and the root module remains dependency-free. Upgrade every installed adapter to v0.10.0 after the adapter tags are published.

### Detection changes

- IP sentence punctuation now remains outside the masked address, including IPv4 tails in IPv6 and hyphenated IP ranges; addresses followed by digits or identifier text still remain excluded and may be missed there.
- Credential masking now accepts arbitrary HTTP auth schemes including quote/backtick token bytes and partially masked credential lists, suffix-based credential keys, Go typed values including underscore and Unicode type names, spaced fmt values after long keys or fields, four quote-escape layers, percent-encoded assignments, backticks, Go assignments, indented YAML blocks and formatted URL userinfo. These forms can mask nonsecret text under credential-like keys or ambiguous fmt fields or quotation; values without a credential key, beyond the escape bound or outside supported grammar may still be missed. Custom sensitive keys replace the default suffix policy.
- PEM and line scanning share normalized private-key frames, including PGP private key blocks and encoded headers/footers; incomplete blocks still mask through EOF and may hide following public text. Non-private labels remain outside this policy.
- SWIFT context accepts common code/number/address key spellings. SWIFT ignores syscall hex register slots, invalid-user slots, underscore-joined identifiers and hardware wire warnings; real BICs placed in those contexts may now be missed. Lowercase and digit-bearing codes and wire-transfer context remain supported.
- ABA ignores explicit double-hummer alignment exception counters and log sequence suffixes; actual routing numbers recorded as those counters or filenames may now be missed. Bare valid-checksum routing numbers remain supported.
- ARN account exclusion now requires a recognized AWS partition and contiguous account digits; non-AWS lookalikes and separated My Number values are detected. Real identifiers placed in syntactically valid AWS account fields can still be missed.

### Fixed

- Canary checks recognize Go hexadecimal byte-list representations, including surrounding bytes.
- Audit input diagnostics identify invalid options and allowed ranges without echoing arguments; JSON masking distinguishes malformed input, resource limits and cancellation using fixed messages.
- Package inventory and documented coverage are checked against Go and the executable gate; real-log prose refers to the generated rates.


## [0.9.0] - 2026-11-17

This minor release closes formatted and escaped credential leaks, handles complete IPv4-embedded IPv6 and streaming PEM spans, and refines context-sensitive detection. The public API and default minimum confidence of 0 are unchanged, and the root module remains dependency-free. Upgrade every installed adapter to v0.9.0 after the adapter tags are published.

### Detection changes

- Mask every credential element in Go fmt maps and slices, quoted Bearer/Basic header values, and assignments inside up to two Go/JSON quote and backslash escape layers; findings retain original byte offsets. A marker prefix no longer exempts the rest of a value.
- Mask embedded IPv4 tails as part of one IPv6 address and extend incomplete PEM private-key blocks to end of input. ScanLines retains PEM state so each material line is reported; truncated blocks can conservatively mask following unrelated text.
- Add access_token, refresh_token, id_token, x-api-key, DB_PASSWORD, Private-Token, client_secret, auth_token and PGPASSWORD to normalized default credential keys. Use WithSensitiveKeys to select an application's exact key policy.
- Exclude ARN account fields from MyNumber, git SCP remotes from email, and attached version labels from IPv4 detection. Require whole-word SWIFT context and direct code introduction after swift; genuinely sensitive values in those excluded contexts can be missed. The default confidence remains 0; review the findings snapshot and application-specific logs before upgrading.

### Fixed

- Match embargotest canaries embedded in standard and URL-safe base64 at every byte alignment, with or without padding; MIME line wrapping and full Unicode escaping still require explicit decoding.
- Print usage and return success for embargo-audit -h and --help, and include short usage for invalid flags without echoing arguments.
- Measure comparison scenarios at the default confidence, disclose deliberate PAN look-alikes beside real-log false-positive rates, and render time-chart gridlines uniformly.

## [0.8.1] - 2026-11-16

### Documentation

- Restore the original README introduction; detection behavior and the public API are unchanged from v0.8.0.

## [0.8.0] - 2026-11-16

This minor release adds the installable embargo-audit command and broadens normalization and joined-key masking. The default minimum confidence remains 0 and the root module remains dependency-free. The corresponding adapters are published at v0.8.1 and require root v0.8.1.

### Detection changes

- Normalize non-ASCII Unicode dash, space and format categories inside tokens, preserving original byte offsets; retain ASCII delimiters.
- Hide every segment of a key path when detection spans a join, and mask whole numeric JSON lexemes including strings emitted by logger encoders.
- Preserve recognized standard console levels in withheld diagnostics while discarding original timestamps and message content.

### Added

- Installable embargo-audit command with streaming comparisons between two scanner settings.
- Changed-statement coverage, detection compatibility and per-package mutation gates, plus category and grammar properties across loggers.
- An independent leak-testing tutorial and measured comparisons including go-masker, with event-time and scenario charts.

## [0.7.0] - 2026-11-16

This minor release closes masking gaps and changes access-log failure behavior. Only requests already canceled when their access record is built receive a detached 100 ms masking budget; failed access records retain their HTTP status or gRPC code and handler duration. The public API and the default minimum confidence of 0 are unchanged. Upgrade the root and every installed adapter to v0.7.0 when the adapter tags are published.

### Fixed

- Scan decoded HTTP query keys and values once without re-encoding, preserve one-pass masking across kinds, and hide Proxy-Authorization credentials.
- Normalize additional Unicode digit separators and ignore interior zero-width and nonbreaking formatting marks while preserving original byte offsets.
- Mask whole fractional or exponential JSON number lexemes whose exact integer value is detected, including slog json.Number values; scan slog byte contents and group-qualified text keys.
- Omit unproven input timestamps from zap and zerolog withheld records so user fields cannot survive through diagnostic metadata.
- Make shared numeric suffix checks and rejected GitHub and Slack token scans linear, with adversarial scaling regression coverage.
- Record HTTP status 0 with response_written=false when a handler panics before writing a final response, then propagate the panic unchanged.
- The v0.7.0 adapters preserve gRPC outcomes and original OTel trace/span IDs and flags in diagnostics, and keep the OTel attribute count independently of SDK environment limits. These modules are released separately after the root.

### Validation

- Require unique, ordered comparison markers and exactly one replacement, and assert complete HTTP and gRPC cancellation records with mutation checks.
- Test detached-budget exhaustion with an internal clock and timeout seam, preserving coverage and masking gates without timing-based serialization.

## [0.6.0] - 2026-11-16

This minor release replaces silently discarded log records with safe withheld diagnostics and retains access records for canceled requests. The public API and the default minimum confidence of 0 are unchanged. Upgrade the root and every installed adapter to v0.6.0 when the adapter tags are published.

### Changed

- Replace failed slog records with a fixed withheld message and attribute count while preserving time and level; retain masked HTTP access records after request cancellation using a detached masking budget.
- The v0.6.0 adapters extend withheld records to zap, zerolog, logrus, OpenTelemetry and Sentry, and retain gRPC unary and stream access records after cancellation. These adapter modules are released separately after the root.

### Fixed

- Reject oversized plain byte slices before slog base64 encoding and bound JSON output growth before appending bytes.

### Documentation

- Explain that encoded-byte limits do not bound user-defined MarshalJSON, LogValue, String or Error methods, and recommend Secret or bounded values for these types.
- Add generated threshold measurements and guidance for choosing a minimum confidence without changing the default.

## [0.5.2] - 2026-11-16

This patch release masks adjacent email-shaped values in one pass and consolidates tests and documentation. Upgrade the root and every installed adapter to v0.5.2.

### Fixed

- Preserve the end of an accepted email domain as the boundary for the next local part, so adjacent values are masked in one pass and repeated MaskJSON calls are idempotent. The fuzz regression also reproduces in v0.5.0. All-Kind adjacency properties additionally cover complete terminal-ID token boundaries and neighboring sort-code formats ([PR #108](https://github.com/nao1215/embargo/pull/108), [f6fafb9](https://github.com/nao1215/embargo/commit/f6fafb9c8cff4d251a2e61e09d9ca20c5434a84d)).

### Changed

- Consolidate tests beside their sources or by integration subject, enforce the test-file budget, and replace development trace history with current behavior and evidence. This test and documentation reorganization does not change the public API or numeric accuracy/false-positive gates ([PR #113](https://github.com/nao1215/embargo/pull/113), [1d2f374](https://github.com/nao1215/embargo/commit/1d2f374c869132e03a6586c194a51369d0dbe6b3); [PR #114](https://github.com/nao1215/embargo/pull/114), [6fa216c](https://github.com/nao1215/embargo/commit/6fa216c07b4c0859109a9bfe89e41ddd1845a993); [PR #115](https://github.com/nao1215/embargo/pull/115), [7ab6bc0](https://github.com/nao1215/embargo/commit/7ab6bc02392ab95bafa1ce615c4eae2c02d6e069)).

### Added

- Detector-change CI jobs enforce frozen per-Kind precision/recall floors, sampled real-log FP/GB ceilings and a +20% paired default-scanner median budget ([e1b3bec](https://github.com/nao1215/embargo/commit/e1b3becd47860a0881b83e1679b0deb55a0c9992)).

- Audit local logs with the isolated tests/cmd/embargo-audit command, reporting per-Kind counts, masked byte offsets and kind-selection guidance ([349bb11](https://github.com/nao1215/embargo/commit/349bb118791c6916ebd18c288616db4937a7e3f1)).

- Optional WithCanaryFragments checks contiguous raw canary pieces of at least 16 bytes in Recorder and Guard; default whole-value checks are unchanged ([7372eda](https://github.com/nao1215/embargo/commit/7372eda4ab7e4bede24b14d9acfd3a23819cc01d)).

## [0.5.1] - 2026-11-16

This patch release fixes sensitive-data leaks in logging and telemetry boundaries and at inclusive confidence thresholds. Upgrade the root module and every installed adapter module to v0.5.1.

### Security

Implementation: [PR #94](https://github.com/nao1215/embargo/pull/94), [299cbe5](https://github.com/nao1215/embargo/commit/299cbe5b2346120545dbb7eadab540ff7f15f12b); [PR #95](https://github.com/nao1215/embargo/pull/95), [7043bb2](https://github.com/nao1215/embargo/commit/7043bb2ac70597458d9d85724469dec0c424eb28); [PR #96](https://github.com/nao1215/embargo/pull/96), [c084990](https://github.com/nao1215/embargo/commit/c08499049f0eed6c82f9655cfd754770659eeefe).

- Preserve original-key context when scanning slog scalars, errors, bound attributes, groups and LogValuer values, which could expose CVVs, client secrets, bank accounts and expiry values in v0.4.0–v0.5.0. The same omission affected HTTP query and redirect-query access logs in v0.5.0, and sensitive boolean/null JSON leaves in MaskJSON and encoded logger adapters in v0.4.0–v0.5.0. Upgrading the root and installed adapters to v0.5.1 fixes these paths.
- Scan both standard slog handler representations before forwarding a scalar. In v0.4.0–v0.5.0, Duration nanoseconds could expose a PAN through JSONHandler, and TextHandler timestamp formatting could expose text missed by the alternate representation. Upgrading the root and installed adapters to v0.5.1 masks a value when either representation matches.
- Rebuild OpenTelemetry float and typed-slice values only from sanitized data after masked-key collisions. The v0.5.0 OTel log and span exporters could restore original PAN values in log bodies, log attributes and span attributes. Upgrading the root and installed adapters to v0.5.1 prevents that restoration.
- Accumulate email and JWT confidence scores as integers before converting to floating point. Core releases v0.0.2–v0.5.0, including earlier module names, could miss email addresses and JWTs at a threshold exactly equal to the documented score; every hook using an affected scanner inherited the miss. Upgrading the root and installed adapters to v0.5.1 restores inclusive-threshold detection and masking.

### Fixed

Implementation: [PR #94](https://github.com/nao1215/embargo/pull/94), [299cbe5](https://github.com/nao1215/embargo/commit/299cbe5b2346120545dbb7eadab540ff7f15f12b); [PR #96](https://github.com/nao1215/embargo/pull/96), [c084990](https://github.com/nao1215/embargo/commit/c08499049f0eed6c82f9655cfd754770659eeefe); [PR #98](https://github.com/nao1215/embargo/pull/98), [f2acba5](https://github.com/nao1215/embargo/commit/f2acba59e498f3b7867ed672db5b56f1212233f0).

- Preserve OTel dropped-attribute counts and other telemetry metadata; reject edits the SDK cannot represent without losing counters.
- Add Scanner.MaskJSONContext and honor cancellation before subsequent detector or value scans in slog, HTTP, gRPC, OTel, Sentry and logrus Entry.Context.
- Apply the shared 64-level depth limit to both WithGroup chains and explicit slog groups, including bound attributes.

### Docs

Implementation: [PR #97](https://github.com/nao1215/embargo/pull/97), [2955f9d](https://github.com/nao1215/embargo/commit/2955f9d287afc3b050e3661c4a1756954ddb1ce9).

- Correct default detector and raw credential-key guidance, and make README-linked examples runnable independently, including OTel exporters and Guard fixtures.

## [0.5.0] - 2026-11-16

This release adds service and telemetry hooks, opt-in national ID detectors and explicit matching contracts. Users upgrading from v0.4.0 should review the default detector and IP behavior changes in [doc/migration.md](https://github.com/nao1215/embargo/blob/v0.17.0/doc/migration.md).

### Service and telemetry hooks

Implementation: [PR #88](https://github.com/nao1215/embargo/pull/88), [76c1692](https://github.com/nao1215/embargo/commit/76c169240e874e100ff007d8c547043af01878ec).

- Add `NewHTTPHandler` in the dependency-free root module for net/http access logs, plus separate `github.com/nao1215/embargo/adapters/grpc`, `github.com/nao1215/embargo/adapters/otel` and `github.com/nao1215/embargo/adapters/sentry` modules. They provide unary/stream server interceptors, log/span exporter wrappers and an error-event `BeforeSend` helper. Existing zap, zerolog and logrus adapters remain separate modules; [adapter Examples and contracts](doc/adapters.md) show each integration.
- HTTP and gRPC mask access records while preserving service requests, responses and errors. OpenTelemetry masks copied telemetry, rejects log batches requiring changes to immutable resource/scope fields and omits span TraceState. Sentry masks a reconstructed event and its sampling context, omits attachments and drops events on masking failure; separate transaction/log/metric callbacks are outside this hook.

### Opt-in national identifiers

Implementation: [PR #88](https://github.com/nao1215/embargo/pull/88), [76c1692](https://github.com/nao1215/embargo/commit/76c169240e874e100ff007d8c547043af01878ec).

- Add 11 kinds: `KindUSSSN`, `KindUSITIN`, `KindUKNINO`, `KindUKNHS`, `KindIndiaAadhaar`, `KindIndiaPAN`, `KindBrazilCPF`, `KindBrazilCNPJ`, `KindChinaResidentID`, `KindKoreaRRN` and `KindCanadaSIN`. Select only the required kinds with `NewScanner(WithKinds(KindUSSSN, KindCanadaSIN))`, or select all 37 built-ins, including entropy and national IDs, with `NewScanner(WithAll())`. `WithKinds` replaces the built-in selection; `NewScanner()` and a zero Scanner keep the 25 default kinds.
- Publish checksum/format validation, confidence policies, exact-span synthetic results and sampled real-log false positives in [country detection](doc/countries.md). These kinds remain opt-in because threshold-zero false positives do not meet the default-selection criteria. Modern Korean RRN detection requires an attached label when the legacy checksum does not apply.

### Detector contracts and adoption guide

Implementation: [PR #87](https://github.com/nao1215/embargo/pull/87), [bde782f](https://github.com/nao1215/embargo/commit/bde782fdde887b75882ed2ac8c1a8f73df479b37); [PR #89](https://github.com/nao1215/embargo/pull/89), [f1f5d80](https://github.com/nao1215/embargo/commit/f1f5d80b6c76cf696ec3202bf8d01b28ce659afd); [PR #90](https://github.com/nao1215/embargo/pull/90), [fb9825a](https://github.com/nao1215/embargo/commit/fb9825a82487ecb8849037594b058c2a0f3f0d18).

- Document matching rules, validation, confidence scores and default selection for every Kind in godoc. Generate the README's 37-kind table from those comments, and check the documented scores and defaults against public scanner behavior. Keep interpretation limits and false-positive guidance in the linked detector guides.
- Reorganize the README around supported outputs, runnable examples and measured evidence, including the new HTTP, gRPC, OpenTelemetry and Sentry boundaries.

### Guard diagnostics and value checks

Implementation: [PR #81](https://github.com/nao1215/embargo/pull/81), [afe881d](https://github.com/nao1215/embargo/commit/afe881d48d3343249becc12f22a7eb42c61c73a3); [PR #83](https://github.com/nao1215/embargo/pull/83), [0839eee](https://github.com/nao1215/embargo/commit/0839eee7502c1b2bd55b5f39e410aba4f71379a1); [PR #86](https://github.com/nao1215/embargo/pull/86), [780b634](https://github.com/nao1215/embargo/commit/780b634915d21ff1782ecd5cde6e1956fb10f949).

- Restore candidate leaking test names in `embargotest.Guard` diagnostics by tracking active, paused and completed tests near observed output. Validate names and their joined representation against canaries, the scanner, character rules and length limits before displaying them; parallel tests and separate stdout/stderr pipes still limit attribution.
- Include the instantiated `Secret` type in `%#v` and `GoString` output while preserving the redaction marker. Make `CheckValue` inspect unexported fmt fields, exposing domain types whose formatters are bypassed there; [migration notes](https://github.com/nao1215/embargo/blob/v0.17.0/doc/migration.md) describe assertion and representation changes.

### Default detection and log false positives

Implementation: [PR #81](https://github.com/nao1215/embargo/pull/81), [afe881d](https://github.com/nao1215/embargo/commit/afe881d48d3343249becc12f22a7eb42c61c73a3); [PR #83](https://github.com/nao1215/embargo/pull/83), [0839eee](https://github.com/nao1215/embargo/commit/0839eee7502c1b2bd55b5f39e410aba4f71379a1).

- Make `KindHighEntropy` opt-in through `WithKinds` or `WithAll`; default scanners, Recorder and Guard no longer report unlabeled entropy candidates. Its confidence remains 0.3 and the default minimum confidence remains zero. Credential assignments and provider prefixes stay enabled by default.
- Exclude unspecified and loopback IPv4/IPv6 addresses from `KindIPAddr` while retaining other private endpoints. Reject additional path/hostname fragments, numeric log tails, operational counters and unquoted Java object references in the affected detectors; see [behavior migration](https://github.com/nao1215/embargo/blob/v0.17.0/doc/migration.md) for the recall trade-offs.

### Severity gates and measured evidence

Implementation: [PR #81](https://github.com/nao1215/embargo/pull/81), [afe881d](https://github.com/nao1215/embargo/commit/afe881d48d3343249becc12f22a7eb42c61c73a3); [PR #82](https://github.com/nao1215/embargo/pull/82), [83e325c](https://github.com/nao1215/embargo/commit/83e325c17805df1ab35f53d115776978bec1b829); [PR #86](https://github.com/nao1215/embargo/pull/86), [780b634](https://github.com/nao1215/embargo/commit/780b634915d21ff1782ecd5cde6e1956fb10f949); [PR #88](https://github.com/nao1215/embargo/pull/88), [76c1692](https://github.com/nao1215/embargo/commit/76c169240e874e100ff007d8c547043af01878ec).

- Add exact-span residual-exposure measurements and a critical-tier gate requiring 100% recall and zero unmasked expected bytes in the committed corpora. Keep severity classification in the test suite and the default threshold at zero; a higher global threshold can drop genuine findings. [Accuracy results](doc/accuracy.md) retain known misses and per-tier trade-offs.
- Publish sampled false-positive estimates from eight checksum-pinned public log datasets (92.4 MB, 819,576 lines), with licenses and classification rules, plus interleaved kind-selection benchmarks and refreshed library comparisons. Preserve raw evidence and source/dependency fingerprints; sampled log estimates and fixture timings are not deployment-wide guarantees, and previously inspected held data is identified as regression data.

### Testing and CI

Implementation: [PR #83](https://github.com/nao1215/embargo/pull/83), [0839eee](https://github.com/nao1215/embargo/commit/0839eee7502c1b2bd55b5f39e410aba4f71379a1); [PR #85](https://github.com/nao1215/embargo/pull/85), [da42803](https://github.com/nao1215/embargo/commit/da42803e6fd74fa4da85917ba12ad731c4d13122); [PR #86](https://github.com/nao1215/embargo/pull/86), [780b634](https://github.com/nao1215/embargo/commit/780b634915d21ff1782ecd5cde6e1956fb10f949); [PR #88](https://github.com/nao1215/embargo/pull/88), [76c1692](https://github.com/nao1215/embargo/commit/76c169240e874e100ff007d8c547043af01878ec); [PR #89](https://github.com/nao1215/embargo/pull/89), [f1f5d80](https://github.com/nao1215/embargo/commit/f1f5d80b6c76cf696ec3202bf8d01b28ce659afd).

- Add metamorphic checks, Quint lifecycle replay, compiled Lean reference vectors, offline oracles, adversarial fuzz seeds and allocation/scaling budgets. Verify prose, policies and the Actions lockfile in CI, pin the Quint release evaluator, check all adapter dependencies without local replacements, retry module downloads and improve caches. Keep heavier mutation/scaling jobs scheduled; CodeRabbit review is best effort, with green CI and resolved review threads required for merging.

## [0.4.0] - 2026-11-15

This release redesigns the public API after the rename to embargo. See [doc/migration.md](https://github.com/nao1215/embargo/blob/v0.17.0/doc/migration.md) for behavior changes.

### Forgotten credentials and output contracts

Implementation: [PR #77](https://github.com/nao1215/embargo/pull/77), [97a0585](https://github.com/nao1215/embargo/commit/97a0585).

- Add `KindCredential`, `KindServiceToken` and `KindHighEntropy` for credential assignments, URL/DSN passwords, provider prefixes and uncertain random-looking tokens; preserve surrounding connection information, mask complete PEM bodies, and reject IBAN reserved check digits. Scanner and output paths retain the caller's confidence policy; publish separate 0, 0.5 and 0.7 results and the entropy trade-off in [accuracy](doc/accuracy.md).

- Add `embargotest.Guard(m, opts...)` for one-line TestMain supervision of stdout, stderr, default slog, t.Log, panic and inherited subprocess output; fail on detected values, canaries, truncation and timeouts, with stream and candidate test names. Add `CheckValue(tb, constructor)` to exercise standard formatting, serialization, templates, slog and wrapped errors with exact failing paths.

- Add `Recorder.Setenv`, `File`, `Header` and `Reader` for standard environment, config-file and HTTP inputs; use the existing Canary as a plain database row value. Cover every new identifier with godoc, runnable Examples and API goldens, and hold homemade types, Secret and Input to the same formatter contract.

- Add generated service leak comparisons for embargo slog/zap, masq, slog-formatter and go-mask, plus in-memory OTel log export, joined-error, HTTP redirect/error and goleak lifecycle checks. Keep the noisy name-analyzer prototype test-only and omit an error wrapper whose Unwrap would re-expose original messages; document both decisions and the standard-interface domain pattern.

### Structured application masking

- Add `Scanner.MaskJSON(data []byte) ([]byte, error)` and `WithSensitiveKeys(keys ...string) ScannerOption` to share detector and normalized key rules across JSON documents, structured slog values and all logger adapters; retain JSON shape, duplicate keys and numeric precision, with bounded work and fixed failures ([optimized JSON traversal](https://github.com/nao1215/embargo/commit/62b655e)) ([PR #76](https://github.com/nao1215/embargo/pull/76), [implementation](https://github.com/nao1215/embargo/commit/66099c0)). The default keys mask opaque passwords, tokens and HTTP authorization/cookie values; callers can extend or replace the set.

- Add `(*Input[T]).Scan(src any) error` for database string/byte columns, copying driver buffers and clearing failed/NULL input; retain the existing text decoder and require explicit Reveal for database writes ([PR #76](https://github.com/nao1215/embargo/pull/76), [implementation](https://github.com/nao1215/embargo/commit/66099c0)). Runnable Examples and API goldens cover each new identifier; docs explain tag migration and why there is no extra tag or ReplaceAttr API.

- Preserve encoded structured Any values in slog JSON output and readable wrapped error text; freeze attached values, mask sensitive groups, and verify application output with plain slog and masq using existing embargotest assertions ([PR #76](https://github.com/nao1215/embargo/pull/76), [implementation](https://github.com/nao1215/embargo/commit/66099c0)). TextHandler displays structured values as compact JSON; Stringer no longer overrides JSON encoding.

- Add versioned head-to-head correctness tests, ten-sample benchmarks, benchstat output, a generated comparison chart and staleness checks; document differences and remaining use cases for masq, slog-formatter, godlp, go-mask, go-masker, cockroachdb/redact, zap and OTel ([PR #76](https://github.com/nao1215/embargo/pull/76), [comparison implementation](https://github.com/nao1215/embargo/commit/66099c0)).

- Add pinned Gosec and daily Trivy filesystem workflows across all modules, with SARIF upload and badges; review the Trivy supply-chain advisory, justify synthetic test findings individually, and update the zerolog adapter's vulnerable x/sys dependency ([PR #76](https://github.com/nao1215/embargo/pull/76), [security changes](https://github.com/nao1215/embargo/commit/66099c0)).

### Accuracy and scanning

- Decode one layer of percent escapes with original byte offsets, lower confidence for business-labeled numeric candidates, reject embedded My Number fragments, and share hint dispatch across selected detectors while removing unnecessary ASCII position maps ([PR #73](https://github.com/nao1215/embargo/pull/73), [implementation](https://github.com/nao1215/embargo/commit/29ce283)). Public API signatures and the default threshold of 0 are unchanged; see the [behavior migration note](https://github.com/nao1215/embargo/blob/v0.17.0/doc/migration.md).

- Separate development and held-out synthetic evaluation, publish both default and 0.7 confidence policies, retain reviewed limits, and extend differential, offset and mutation assertions ([PR #73](https://github.com/nao1215/embargo/pull/73), [assertions](https://github.com/nao1215/embargo/commit/789318d)). The stricter SWIFT context experiment was rejected after held-out recall regressed.

- Bound percent-decoding map capacity without addition, skip unused decoding for empty or custom-only scanners, recognize business labels at query boundaries, and reject invalid accuracy-set selections ([PR #73](https://github.com/nao1215/embargo/pull/73), [allocation bound](https://github.com/nao1215/embargo/commit/5a32a38), [review fixes](https://github.com/nao1215/embargo/commit/7d54404)).

### Follow-up review

- Add optional zap, zerolog and logrus modules with JSON output masking, runnable Examples, real-output tests, all-platform CI and a nested-module release plan ([PR #70](https://github.com/nao1215/embargo/pull/70), [implementation](https://github.com/nao1215/embargo/commit/586448a)).

- Replace the README walls of text with checked outputs and generated accuracy/benchmark figures, expand the synthetic corpus, scope unchecked fmt printing to Examples, audit godoc, align badges and add attributed gopher artwork ([PR #70](https://github.com/nao1215/embargo/pull/70), [integration](https://github.com/nao1215/embargo/commit/6eed0a6)).

- Avoid redundant expiry overlap probes before parsing candidates, preserving overlap behavior while reducing measured scan time ([PR #70](https://github.com/nao1215/embargo/pull/70), [implementation](https://github.com/nao1215/embargo/commit/4c5281e)).

- Skip expensive Go checks for documentation-only changes while keeping README/Example checks and CodeQL ([PR #66](https://github.com/nao1215/embargo/pull/66), [cafc62e](https://github.com/nao1215/embargo/commit/cafc62e)).

### Added

- Replace the logo with embargo branding and add a 1280x640 Open Graph image at doc/images/ogp.png for repository settings ([PR #64](https://github.com/nao1215/embargo/pull/64), [573fa10](https://github.com/nao1215/embargo/commit/573fa10)).

- Publish per-detector precision/recall from a labeled synthetic corpus and real Go benchmark samples for Scanner, Mask, Recorder and slog. Make targets generate README tables and tests reject stale output; introduce use cases and installation requirements at the README entrance ([PR #63](https://github.com/nao1215/embargo/pull/63), [1f2b4c2](https://github.com/nao1215/embargo/commit/1f2b4c2)).

- NewSlogHandler masks messages, keys, groups and values with an explicit scanner, freezes WithAttrs values, preserves metadata and clean scalar types, and converts opaque Any/error values to scanned strings. Normalization or detector panics, including panic(nil) compatibility mode, suppress output with a fixed error ([PR #61](https://github.com/nao1215/embargo/pull/61), [8d439b0](https://github.com/nao1215/embargo/commit/8d439b0)).

- Exercise Secret/Input with real fmt, slog, JSON/XML, templates, zap, zerolog, logrus, OTel, Sentry, HTTP and child panic outputs. Generate the README Tested outputs table from the executed acceptance cases; external SDKs remain in tests/go.mod ([PR #60](https://github.com/nao1215/embargo/pull/60), [fa73d0b](https://github.com/nao1215/embargo/commit/fa73d0b)).

- embargotest captures writers, HTTP status/headers/body/trailers and child test processes, verifies expected content, and checks every output with the scanner and an encoded canary. Allow kinds or exact fixture values independently of the canary; empty output, cut-off output, repeated interim headers exceeding the budget, and child lifecycle failures cannot pass ([PR #59](https://github.com/nao1215/embargo/pull/59), [3649bed](https://github.com/nao1215/embargo/commit/3649bed)).

- Secret and Input are now root runtime types. NewSecret wraps a shallow copy with unexported-pointer storage and [REDACTED] display through fmt, slog, JSON, text and XML; Reveal explicitly returns the value. Input copies decoded strings/bytes into a snapshot and rejects marker round trips, including JSON escaping and base64 ([PR #58](https://github.com/nao1215/embargo/pull/58), [c49392c](https://github.com/nao1215/embargo/commit/c49392c)).


Implementation: [PR #56](https://github.com/nao1215/embargo/pull/56), [89eb73c](https://github.com/nao1215/embargo/commit/89eb73c).

### Breaking changes

- Runtime operations now live in embargo. Use NewScanner(WithKinds(KindEmail, KindPAN)) instead of individual WithEmail/WithPAN options or detector.NewX constructors; detector implementations are internal. NewScanner() and a zero Scanner enable all built-ins, including IP addresses and context-based detectors; WithKinds() explicitly selects none and WithAll() resets all.
- Finding has Kind, Start, End and Confidence. Replace DetectorName, SensitiveKind, Is/IsX and Kind() with Kind comparisons, and RawValue with a slice of the original input. Detail structs, typed accessors, interpretation enums, Level and public normalization are removed; use a domain parser when interpretation is needed.
- Detector requires only Scan([]byte) []Finding. Implement custom matching directly instead of detector.NewRegex, Name and Hints. WithDetector appends independently of built-ins; nil or typed-nil detectors and invalid findings panic with fixed messages.
- ScannerOption is sealed and replaces Option. WithKinds replaces the built-in selection; custom registrations no longer replace one another by name. Invalid WithMinConfidence values panic instead of clamping.
- All overlaps are retained and findings are sorted by start, descending end, kind and descending confidence. Remove WithoutDedup and WithSortByPosition. ScanReader is removed; explicitly bound and read the input before Scan, or use ScanLines for independent lines.
- Use embargo.Mask instead of mask.MaskAll with Redact. The replacement is [REDACTED], overlapping spans are merged, and invalid ranges redact the entire text. MaskFunc replaces custom Strategy, Last4, First1Last4, Partial and Hash; its callback receives the merged span and the highest-confidence kind. Filter findings explicitly for per-kind policies.
- Go 1.26.11 is the minimum in both modules, keeping the previous supported Go series and the net/http fix for GO-2026-6859 required by the upcoming HTTP test recorder. The root module still has no requirements.

### Fixed

- Fail Recorder checks when a custom detector panics with nil under GODEBUG=panicnil=1. Successful checks now require the scanner to finish; validator panics remain failures with fixed diagnostics ([PR #62](https://github.com/nao1215/embargo/pull/62), [72e9a6a](https://github.com/nao1215/embargo/commit/72e9a6a)).

- Check normalization-map capacity before sentinel addition and backing-size arithmetic. CodeQL found the two potentially overflowing allocation expressions; a boundary regression checks the arithmetic without allocating oversized input.

- PAN no longer reports numeric fragments embedded in alphanumeric or underscore-delimited identifiers. Compatibility repetition exposed a Sentry event ID false positive; boundary regressions include full-width digits and preserve URL-encoded separators.

- Do not classify decimal components or RFC3339 fractional seconds as ABA routing numbers, even if their digits satisfy the routing checksum. A regression test reproduces the timestamp false positive discovered through real slog output.

### Testing

- Lock the runtime API, constant values and complete method sets with a go/types golden, reject public struct embedding, and require recognized runnable Examples for every public identifier. Preserve internal detection fixtures, independent checksum oracles and rapid shrinking tests.
- Enable the 77-linter union audited across the owner's Go libraries, with named and explained local suppressions, and enforce dependency direction with depguard and go-arch-lint. Add interval-union property and fuzz tests for caller-controlled masking.


## [0.3.0] - 2026-11-15

### Changed

- The module path is now github.com/nao1215/embargo and the root package is `embargo`; replace `github.com/nao1215/sensitive` with `github.com/nao1215/embargo` in imports and `sensitive.` with `embargo.` in code. The API is otherwise unchanged ([PR #54](https://github.com/nao1215/embargo/pull/54), [008655d](https://github.com/nao1215/embargo/commit/008655d)).

## [0.2.2] - 2026-11-15

### Deprecated

- The module is deprecated: development continues as github.com/nao1215/embargo, and this is the last release under github.com/nao1215/sensitive. The `go.mod` deprecation comment makes `go get` and `go list -m -u` point to the new path ([PR #53](https://github.com/nao1215/embargo/pull/53)).

### Changed

- Raise the separate test module minimum to Go 1.26.0, required by `golang.org/x/crypto` v0.59.0; the root library still requires Go 1.22 and has no external dependencies ([PR #52](https://github.com/nao1215/embargo/pull/52), [33da87a](https://github.com/nao1215/embargo/commit/33da87af35dbb5b4ab64b884a29c5daf12279235)).
- Shorten the README around runnable examples, move detailed contracts and benchmarks to linked documentation, and condense public API comments while retaining detector algorithms; keep Contributors unchanged ([PR #51](https://github.com/nao1215/embargo/pull/51), [21ac25a](https://github.com/nao1215/embargo/commit/21ac25a6073b43ddd2c5f8501eda38924dd76bb2)).
- Consolidate runnable examples and check README snippets, expected output, and godoc example placement in the test suite without changing library behavior or dependencies ([PR #51](https://github.com/nao1215/embargo/pull/51), [21ac25a](https://github.com/nao1215/embargo/commit/21ac25a6073b43ddd2c5f8501eda38924dd76bb2)).

## [0.2.1] - 2026-11-14

### Fixed

- Space-delimited UK sort codes followed by whitespace or prose are detected without accepting a following numeric group; classic GitHub tokens require exactly 36 body characters as documented ([PR #47](https://github.com/nao1215/embargo/pull/47), [40d3c95](https://github.com/nao1215/embargo/commit/40d3c95)).

### Changed

- Property-based testing now uses rapid in an isolated test-only module, with specification generators, shrinking, path and masking properties, a labeled recall corpus, targeted mutation checks, and merged cross-module coverage; the root library remains dependency-free ([PR #47](https://github.com/nao1215/embargo/pull/47), [40d3c95](https://github.com/nao1215/embargo/commit/40d3c95)).

## [0.2.0] - 2026-11-14

### Added

- IBAN detection now covers all 89 country formats in SWIFT registry release 103, including 17 previously missing countries ([PR #45](https://github.com/nao1215/embargo/pull/45), [5552698](https://github.com/nao1215/embargo/commit/5552698)).

### Fixed

- IBANs followed by spaces and another word retain their complete original value instead of being rejected; extraction stops at the country-specific length before checking MOD 97 ([PR #45](https://github.com/nao1215/embargo/pull/45), [a66ecbc](https://github.com/nao1215/embargo/commit/a66ecbc)).
- Percent-encoded log/query separators now delimit values consistently, including numeric values whose scanners previously consumed escape digits; malformed escapes are checked against original bytes before full-width normalization, and contextual extractors no longer include escape digits in CVV, expiry, account, trace, or merchant values ([PR #45](https://github.com/nao1215/embargo/pull/45), [3dd2718](https://github.com/nao1215/embargo/commit/3dd2718)).

- The merchant ID detector no longer reports a terminal ID inside a merchant ID it already reported. "Merchant ID A00000000A00000 TID 000" gave both `A00000000A00000` and `00000000`, because only the start offset was checked for duplicates, not the whole range. Found by the scheduled `FuzzScanner` run ([PR #17](https://github.com/nao1215/embargo/pull/17), [5f1042d](https://github.com/nao1215/embargo/commit/5f1042d)).

## [0.1.2] - 2026-09-28

### Fixed

- The card expiry detector no longer reports a second, overlapping date inside one it already reported. "exp 01/01/00" gave both `01/01` and `01/00`, because "exp" is matched once per case variant and each match searched the same range again; "有効期限 01/01/00", matched once, gave only `01/01`. Found by the new `FuzzScanner`.
- The email detector no longer accepts a domain that starts with `.`: "user@.com" and "user@.example.com" were reported with full confidence although the first domain label is empty. Found by the new `FuzzScanner`.

## [0.1.1] - 2026-09-12

### Changed

- The supported Go floor is 1.22 instead of 1.24. Nothing in the tree needs a newer Go: 1.22 is where the detectors' range-over-int stops compiling, so that is the real minimum, and two more Go releases can now use this library. The unit-test matrix runs that floor and the newest release, and the GitHub Actions pins move to `actions/checkout@v7` / `actions/setup-go@v7`.
- CI cross-builds the module for FreeBSD, OpenBSD and NetBSD. A library is reached by `go get` from whatever machine its caller has, and nothing was checking that those three still compile.

### Removed

- The Go Report Card badge. The service is retired and its badge now answers `go report: retired`, which is a line of README saying nothing about this library.

## [0.1.0] - 2026-07-01

### Added

- Developer credential detectors: four new detectors for secrets commonly leaked in source, CI logs, and command lines.
  - `WithGitHubToken()` (`NameGitHubToken`): classic GitHub tokens (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36 base62 chars) and fine-grained PATs (`github_pat_` + 22+ chars). Detail: `GitHubTokenDetail{TokenType}`.
  - `WithSlackToken()` (`NameSlackToken`): Slack API tokens (`xoxb-`/`xoxp-`/`xoxa-`/`xoxo-`/`xoxr-`/`xoxs-`). Detail: `SlackTokenDetail{TokenType}`.
  - `WithGoogleAPIKey()` (`NameGoogleAPIKey`): Google API keys (`AIza` + 35 chars). Detail: `GoogleAPIKeyDetail`.
  - `WithPrivateKeyPEM()` (`NamePrivateKeyPEM`): PEM private key headers (`-----BEGIN [ALGO ]PRIVATE KEY-----` for RSA/EC/DSA/OpenSSH/PKCS#8). Detail: `PrivateKeyPEMDetail{KeyType}`.

  All four are classified as `KindCredential`, use hint-based pre-filtering with dedicated byte scanners (no regular expressions), and are included in `WithAll()`. Findings expose `Is*` predicates and `*Detail()` accessors consistent with the existing detectors.

## [0.0.3] - 2026-02-10

### Fixed

- ScanLines buffer limit increased to 1 MB ([6ee98e3](https://github.com/nao1215/embargo/commit/6ee98e3)): The internal `bufio.Scanner` buffer now starts at 64 KB and grows up to 1 MB (previously limited to the default 64 KB). Lines exceeding 1 MB return `bufio.ErrTooLong`. The doc comment now documents this limitation explicitly.
- ScanLines callback receives a safe copy of line bytes ([216ce24](https://github.com/nao1215/embargo/commit/216ce24)): The `line` slice passed to the ScanLines callback is now an independent copy, safe to retain after the callback returns. Previously, the slice pointed into the `bufio.Scanner` internal buffer, which was overwritten on the next `Scan()` call.
- Confidence values clamped to [0, 1] ([2802566](https://github.com/nao1215/embargo/commit/2802566)): `WithMinConfidence` and `detector.NewRegex` now clamp the confidence parameter to the valid range. Values below 0 are treated as 0 and values above 1 are treated as 1.

### Changed

- Clarified minConfidence ordering in documentation ([cc8d13d](https://github.com/nao1215/embargo/commit/cc8d13d)): The `Scanner.Scan` and `WithMinConfidence` doc comments now explicitly state that the confidence threshold is applied after deduplication and sorting, so dedup always sees the full candidate set.
- Extracted duplicated ASCII helpers to `internal/ascii` ([50a6846](https://github.com/nao1215/embargo/commit/50a6846)): `hasASCIILetter`, `asciiLowerCopy`, and `toLowerASCII` were duplicated between `scanner.go` and `detector/context.go`. They are now shared via the `internal/ascii` package, eliminating the risk of future divergence.
- Pre-computed keyword cache for context-based detectors ([7d56c0f](https://github.com/nao1215/embargo/commit/7d56c0f)): Introduced `keywordSet` type that pre-computes lowered keyword forms once at initialization. Context-based detectors (CVV, ACH, card expiry, merchant ID, bank account) no longer call `ascii.LowerCopy` per keyword on every `Scan` invocation.

### Tests

- ScanLines ErrTooLong regression test ([b71bf3d](https://github.com/nao1215/embargo/commit/b71bf3d)): Verifies that lines exceeding the 1 MB buffer return `bufio.ErrTooLong`.
- ScanLines buffer copy safety test ([5e24472](https://github.com/nao1215/embargo/commit/5e24472)): Verifies that retained `line` slices from the callback are not corrupted by subsequent scans.
- WithMinConfidence boundary value tests ([cf0a3f0](https://github.com/nao1215/embargo/commit/cf0a3f0)): Verifies that a finding with confidence exactly equal to the threshold is included, and one below is excluded.
- RawValue == input[Start:End] invariant test ([54eaa2c](https://github.com/nao1215/embargo/commit/54eaa2c)): Verifies across all built-in detectors that every finding's `RawValue` matches the corresponding `input[Start:End]` slice, preventing mask output corruption.

## [0.0.2] - 2026-02-08

### Added

- Stream scanning API ([06cc2b1](https://github.com/nao1215/embargo/commit/06cc2b1)): `ScanReader(io.Reader)` for in-memory scanning and `ScanLines(io.Reader, callback)` for memory-efficient line-by-line streaming. Ideal for log files and large text streams.
- Bitcoin (BTC) address detector ([a35fec8](https://github.com/nao1215/embargo/commit/a35fec8)): Detects P2PKH (prefix '1'), P2SH (prefix '3'), Bech32 SegWit v0 (prefix 'bc1q'), and Bech32m Taproot v1–v16 (prefix 'bc1p') addresses. Validates Base58Check (double SHA-256 checksum) for legacy addresses and Bech32/Bech32m polynomial checksums (BIP-173/BIP-350) for SegWit/Taproot addresses. Confidence: 0.95.
- Ethereum (ETH) address detector ([a35fec8](https://github.com/nao1215/embargo/commit/a35fec8)): Detects Ethereum addresses (0x + 40 hex characters). Validates EIP-55 mixed-case checksums using Keccak-256. Confidence: 0.80 for all-lowercase/all-uppercase, 0.95 for EIP-55 validated addresses.
- Keccak-256 hash implementation ([a35fec8](https://github.com/nao1215/embargo/commit/a35fec8)): Minimal Keccak-f[1600] sponge construction for EIP-55 checksum validation. Zero external dependencies — uses only the Go standard library.
- `WithBTC()` and `WithETH()` scanner options ([a35fec8](https://github.com/nao1215/embargo/commit/a35fec8)): Enable individual cryptocurrency address detection.
- `BTCDetail()` and `ETHDetail()` finding accessors ([a35fec8](https://github.com/nao1215/embargo/commit/a35fec8)): Type-safe access to detector-specific details (address type, EIP-55 validation status).
- `IsBTC()` and `IsETH()` finding helpers ([a35fec8](https://github.com/nao1215/embargo/commit/a35fec8)): Quick detector type checks.
- Kind mapping ([a35fec8](https://github.com/nao1215/embargo/commit/a35fec8)): Both BTC and ETH are classified as `KindFinancial`.
- Japanese phone number format expansion ([46d2db8](https://github.com/nao1215/embargo/commit/46d2db8)): Added IP phone (050), M2M/IoT (020), and FMC service (060) prefix detection. Enhanced `JPPhoneDetail` with `JPPhoneType` classification.
- Bank account full-width digit support ([46d2db8](https://github.com/nao1215/embargo/commit/46d2db8)): Bank account detector now normalizes full-width digits for Japanese input.

### Changed

- Reduced cyclomatic complexity ([4b0e022](https://github.com/nao1215/embargo/commit/4b0e022)): Refactored detector implementations (PAN, email, JWT, IBAN, IP address, sort code, SWIFT/BIC, etc.) and scanner internals to reduce cyclomatic complexity and improve maintainability.

## [0.0.1] - 2026-02-08

Initial release of the `sensitive` library.

### Added

- Core scanning engine ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Multi-stage filtering pipeline with hint-based pre-filter (SIMD-optimized `bytes.Contains`), detector execution, and result dedup/sort.
- Scanner options: `WithAll()`, individual `With*()` options, `WithSortByPosition()`, `WithoutDedup()`, `WithCustomDetector()` for user-defined detectors.
- Confidence scoring: Every finding includes a confidence level (0.0--1.0) based on structural validation, checksums, and context keywords.

#### Detectors

- PAN (Payment Card Number) ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects Visa, Mastercard, Amex, Discover, JCB, Diners Club, and UnionPay card numbers with Luhn checksum validation. Supports hyphenated, spaced, and contiguous formats. Full-width digit normalization for Japanese input.
- Email ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Heuristic email address detection using `@` as a pivot point. Validates local and domain parts, TLD, and RFC 5321 label boundary rules. Confidence boosted by known TLD matching.
- Japanese Phone Number ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects mobile (090/080/070), landline (03/06/etc.), and toll-free (0120/0800) Japanese phone numbers. Full-width digit normalization. Prefix-based classification.
- My Number (Japanese national ID) ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects 12-digit My Number with official check digit validation (modular arithmetic per specification). Context keyword support (Japanese/English).
- JWT (JSON Web Token) ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects JWTs via the `eyJ` prefix (base64url of `{"`). Validates three-part structure, decodes header JSON, and extracts the `alg` field. Supports unsigned JWTs (alg:none, CVE-2015-9235). Leading boundary check prevents false matches inside longer base64url strings.
- AWS Access Key ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects AWS access key IDs (`AKIA` prefix + 16 uppercase alphanumeric characters). Context keyword support for key/secret pairs.
- IBAN (International Bank Account Number) ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects IBANs with ISO 13616 mod-97 checksum validation. Supports all standardized country code prefixes and lengths.
- IP Address ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects IPv4 and IPv6 addresses. Uses `net.ParseIP` for validation. Boundary checks reject IPs embedded in identifiers (leading/trailing alphanumeric, `_`, `-`).
- SWIFT/BIC ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects SWIFT/BIC codes (8 or 11 characters). Validates bank code, country code (ISO 3166-1 alpha-2), location code, and optional branch code structure.
- US ABA Routing Number ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects 9-digit ABA routing transit numbers. Validates Federal Reserve routing symbol prefix (01-12, 21-32, 61-72, 80) and ABA checksum (3-7-1 weighted mod-10).
- UK Sort Code ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects UK bank sort codes in `XX-XX-XX` or `XX XX XX` format. Date-like pattern disambiguation with context keyword fallback. Rejects all-zero sort codes (00-00-00).
- CVV/CVC/CID ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Context-based detection of 3-4 digit card verification values near keywords (CVV, CVC, CID, security code, etc.). Japanese keyword support.
- Card Expiry ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Context-based detection of card expiration dates (MM/YY, MM/YYYY, MM-YY). Validates month range (01-12) and year range. Japanese keyword support.
- Payment Token ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Detects Stripe (`sk_live_`, `pk_live_`, `sk_test_`, `pk_test_`), Square (`sq0atp-`, `sq0csp-`), and PayPal (`access_token$`) API keys/tokens.
- Bank Account ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Context-based weak detection of bank account numbers (4-17 digits) near banking keywords. Japanese and English keyword support. Holder name context boosts confidence.
- ACH Trace Number ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Context-based detection of 15-digit ACH trace numbers. Validates ODFI routing prefix against Federal Reserve routing symbol ranges.
- Merchant/Terminal ID ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Context-based detection of merchant IDs (MID) and terminal IDs (TID) near keywords. Validates alphanumeric sequences of 8-15 characters.
- Custom Detector ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Users can register custom detectors implementing the `Detector` interface via `WithCustomDetector()`. A `RegexDetector` helper is provided for regex-based detection.

#### Masking

- mask package ([13fca9a](https://github.com/nao1215/embargo/commit/13fca9a)): Optional masking helper with `Mask()` for single findings and `MaskAll()` for multiple findings. Built-in strategies: `StrategyFull` (full masking) and `StrategyPartial` (preserve first/last N characters).

#### Architecture

- Zero external dependencies: Uses only the Go standard library.
- Multi-stage filtering: Hint-based pre-filtering with case-insensitive ASCII matching skips detectors early, minimizing scan cost.
- Pre-computed hint cache: Hint lowercase normalization is computed once at `NewScanner` construction, not per-scan.
- O(n log n) overlap detection: Dedup uses confidence-descending greedy selection with binary search for overlap checking.
- Full-width digit normalization: Transparent handling of Japanese full-width digits (U+FF10--U+FF19) for PAN, phone, and My Number detection.
- Deterministic output: Findings are sorted by confidence (descending), then by byte offset and detector name for fully reproducible results.

[0.5.2]: https://github.com/nao1215/embargo/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/nao1215/embargo/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/nao1215/embargo/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/nao1215/embargo/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/nao1215/embargo/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/nao1215/embargo/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/nao1215/embargo/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/nao1215/embargo/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/nao1215/embargo/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/nao1215/embargo/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/nao1215/embargo/compare/v0.0.3...v0.1.0
[0.0.3]: https://github.com/nao1215/embargo/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/nao1215/embargo/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/nao1215/embargo/releases/tag/v0.0.1
