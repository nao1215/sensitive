# Runtime masking and output checks

## What runs where?

| Tool | Input and use |
|---|---|
| [gitleaks](https://github.com/gitleaks/gitleaks) | Scan Git history, directories or stdin for secrets. |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | Scan repositories, files and other configured sources. |
| [Presidio](https://microsoft.github.io/presidio/) | Detect and anonymize personal data with Python analyzers and services. |
| Secret wrappers | Hide values explicitly wrapped by the application; wrapping does not discover sensitive text. |
| embargo | Scan and mask text inside a Go program, then observe real output in tests. |

These tools can be used together. Repository scanning and runtime masking observe different inputs.

## What does embargo change?

`NewSlogHandler` scans messages and attributes before forwarding a log record. `NewSecret` hides explicitly wrapped values from supported formatting and encoding interfaces. `embargotest` captures log writers, HTTP responses and test child processes, then checks their bytes for a canary and configured detector findings.

The [slog tests](../slog_handler_test.go), [formatting tests](../secret_test.go) and [output tests](../tests/compatibility_integration_test.go) show those boundaries. A custom detector can add an application token pattern; a canary is only a runtime pattern when a detector recognizes it.

[Support maintenance](https://github.com/sponsors/nao1215).
