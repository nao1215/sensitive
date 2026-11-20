---
title: Compare
description: What other Go masking libraries and embargo catch on the same service output, what none of them catch, and how fast each one is.
toc: true
---

## Service output

Each library logs the same service scenarios. A catch means the planted value was removed; partial masks count. go-masker v3 `Sensitive` ties `Secret` on fmt, JSON, XML and slog, and masq, go-masker and go-mask catch a tag-only value that embargo misses.

![Scenario catch rate](doc/images/scenario-catch.svg)

<!-- leak-scenarios:start -->
| Service output | embargo slog | embargo zap | pii-shield v3.0.0 | ferret-scan v2.4.3 | masq v0.2.3 | slog-formatter v1.3.0 | go-mask v0.6.2 | go-masker v0.6.1 | godlp v1.2.15 |
|---|---|---|---|---|---|---|---|---|---|
| Password under the key `password` | caught | caught | caught | caught | caught | caught | caught | caught | leaked |
| Config struct holding a database DSN | caught | caught | caught | leaked | caught | leaked | leaked | caught | leaked |
| DSN inside a wrapped error | caught | caught | caught | leaked | caught | leaked | leaked | caught | leaked |
| DSN and an API key joined with errors.Join | caught | caught | caught | leaked | leaked | leaked | leaked | caught | leaked |
| Bearer header value in a log message | caught | caught | caught | leaked | leaked | leaked | leaked | caught | leaked |
| Third-party API key in a log message | caught | caught | caught | leaked | leaked | leaked | leaked | leaked | leaked |
| Redirect URL query, never logged | leaked | leaked | leaked | leaked | leaked | leaked | leaked | leaked | leaked |
<!-- leak-scenarios:end -->

The last row is a URL query that a redirect sends to the browser. No logging library sees it; an output test does. [Exact outputs and setup](doc/comparison.md)

## Speed

<!-- speed-summary:start -->
On the same five JSON slog events, embargo is 1.09 to 1.60 times faster than go-masker given the same email and card rules, and embargo's default scanner is 1.83 to 5.79 times faster than pii-shield's default policy. [Time per event](doc/comparison.md#time-and-allocations)
<!-- speed-summary:end -->

![Time per log event](doc/images/log-event-time.svg)

Each library is the newest release that builds with embargo's minimum Go 1.26.11, and the timed rules match where both sides have them. [Configurations, medians and allocations](doc/comparison.md#time-and-allocations) · [Per-detector benchmarks](doc/benchmarks.md)

## Where a logging policy stops

Each case is a small Go program that writes a planted secret through one application path: a struct field added after its masking rules were written, an error from an HTTP client, a DSN, a dumped header and eight others. Four approaches mask the same output, then the same embargotest recorder checks it. Masked means the secret disappeared, detected means it survived masking and the test caught it, missed means both let it through.

<!-- adoption-cases:start -->
| Application path | masq tags | Manual redact | Key denylist | embargo |
|---|---|---|---|---|
| added struct field | detected | detected | detected | masked |
| client error | detected | detected | detected | masked |
| HTTP query | detected | masked | detected | masked |
| wrapped error | detected | masked | detected | masked |
| DSN password | detected | detected | detected | masked |
| header dump | detected | detected | detected | masked |
| unwrapped logger | detected | detected | detected | detected |
| card last four | missed | missed | missed | missed |
| truncated card | missed | missed | missed | missed |
| base64 token | detected | detected | detected | masked |
| hex token | detected | detected | detected | detected |
| split token lines | missed | missed | missed | missed |
<!-- adoption-cases:end -->

masq v0.2.3 uses its documented `WithTag("secret")` in the tag column and its field-name policy for Password, password, token and authorization in the denylist column. The manual column replaces 13–19 digit cards and password or token assignments in strings and errors. The embargo column is `NewSlogHandler` with `NewScanner()` defaults. [The runnable cases](tests/cases_test.go)

- The unwrapped logger writes through `log.New` and skips every slog handler. Only the output test catches it.
- Last-four and eight-digit card fragments are not card numbers to any detector, and the split token crosses two JSON records. These need a policy of their own.
- A hex token is not decoded by the detectors, but the canary check catches it.

Each check of the recorder on the output after embargo masking, on its own. Clear means this check did not fire, which includes a value that was already masked:

<!-- check-independence:start -->
| Output after embargo masking | Detector only | Whole canary only | Canary with 16-byte fragments |
|---|---|---|---|
| added struct field | clear | clear | clear |
| client error | clear | clear | clear |
| HTTP query | clear | clear | clear |
| wrapped error | clear | clear | clear |
| DSN password | clear | clear | clear |
| header dump | clear | clear | clear |
| unwrapped logger | detected | detected | detected |
| card last four | clear | clear | clear |
| truncated card | clear | clear | clear |
| base64 token | clear | clear | clear |
| hex token | clear | detected | detected |
| split token lines | clear | clear | detected |
<!-- check-independence:end -->

## Accuracy

<!-- real-logs-summary:start -->
15 public datasets, 239.9 MB, 1,048,835 lines of LogHub system logs plus web access, Kubernetes audit and CloudTrail logs. [Measured false positives](doc/real-logs.md) are sample estimates on previously seen splits, with no recall claim. [Licenses and classification rules](doc/accuracy.md#public-system-logs)
<!-- real-logs-summary:end -->

[Per-detector precision and recall on a held-out synthetic set](doc/accuracy.md) · [Credential detectors](doc/credentials-accuracy.md) · [Country identifiers](doc/countries.md)
