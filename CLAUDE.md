# sensitive

sensitive is a Go library for detecting sensitive data in text. It detects credit card numbers (PAN), email addresses, phone numbers, My Number (Japanese national ID), and other confidential information, returning the position, type, and confidence level of each finding. Masking is optional — the library focuses on detection, allowing users to implement their own masking logic using the detection results.

## Codebase Information
### Development Commands
- `make test`: Run tests and measure coverage (generates cover.out file, viewable in browser with cover.html)
- `make lint`: Code inspection with golangci-lint (.golangci.yml configuration)
- `make clean`: Delete generated files
- `make tools`: Install dependency tools (golangci-lint, octocov)
- `make benchmark`: Run benchmark tests

### Key Features
- Detection-first design: Detection is the core, masking is optional
- Zero dependencies: Standard library only, no external dependencies
- Multi-stage filtering: Hint-based pre-filtering with bytes.Contains (SIMD-optimized) skips 99%+ of non-matching lines
- Japanese data type support: My Number, Japanese phone numbers, full-width digit normalization
- Confidence scoring: Each finding includes a confidence level (0.0-1.0)
- Custom detectors: Users can register their own detectors via the Detector interface

### Architecture
- `sensitive.go`: Core definitions (Scanner, Finding, Detector interfaces)
- `scanner.go`: Scanner implementation with multi-stage filtering
- `finding.go`: Finding struct and related types
- `detector/`: Individual detector implementations (PAN, email, phone, etc.)
- `mask/`: Optional masking helper package

## Development Rules
- Test-Driven Development: We adopt the test-driven development promoted by t-wada (Takuto Wada). Always write test code and be mindful of the test pyramid.
- Working code: Ensure that `make test` and `make lint` succeed after completing work.
- Sponsor acquisition: Since development incurs financial costs, we seek sponsors via `https://github.com/sponsors/nao1215`. Include sponsor links in README and documentation.
- Contributor acquisition: Create developer documentation so anyone can participate in development and recruit contributors.
- Comments in English: Write code comments in English to accept international contributors.
- User-friendly documentation comments: Write detailed explanations and example code for public functions so users can understand usage at a glance.
- Detection logic documentation: Always document the detection logic in documentation comments for each detector. This helps users understand how detection works and what to expect.

## Coding Guidelines
- No global variables: Do not use global variables. Manage state through function arguments and return values.
- Coding rules: Follow Golang coding rules. [Effective Go](https://go.dev/doc/effective_go) is the basic rule.
- Package comments are mandatory: Describe the package overview in `doc.go` for each package. Clarify the purpose and usage of the package.
- Comments for public functions, variables, and struct fields are mandatory: When visibility is public, always write comments following go doc rules.
- Remove duplicate code: After completing your work, check if you have created duplicate code and remove unnecessary code.
- Error handling: Use `errors.Is` and `errors.As` for error interface equality checks. Never omit error handling.
- Documentation comments: Write documentation comments to help users understand how to use the code. In-code comments should explain why or why not something is done.
- Zero external dependencies: This library must have zero external dependencies. Use only the Go standard library.
- Performance first: Minimize scan cost. Use hint-based pre-filtering (bytes.Contains) before expensive operations. Avoid regular expressions unless absolutely necessary — prefer dedicated parsers and domain rule validation.
- CHANGELOG.md maintenance: When updating CHANGELOG.md, always include references to the relevant PR numbers and commit hashes with clickable GitHub links. Format examples:
  - **Feature description ([abc1234](https://github.com/nao1215/sensitive/commit/abc1234))**: Detailed explanation of the change
  - **Feature description (PR #123, [abc1234](https://github.com/nao1215/sensitive/commit/abc1234))**: When both PR and commit are relevant

## Testing
- [Readable Test Code](https://logmi.jp/main/technology/327449): Avoid excessive optimization (DRY) and aim for a state where it's easy to understand what tests exist.
- Clear input/output: Create tests with `t.Run()` and clarify test case input/output. Test cases clarify test intent by explicitly showing input and expected output.
- Test descriptions: The first argument of `t.Run()` should clearly describe the relationship between input and expected output.
- Test granularity: Aim for 80% or higher coverage with unit tests.
- Parallel test execution: Use `t.Parallel()` to run tests in parallel whenever possible.
- Using `octocov`: Run `octocov` after `make test` to confirm test coverage exceeds 80%.
- Cross-platform support: Tests run on Linux, macOS, and Windows through GitHub Actions.
- Test data: Never use real sensitive data. Use well-known test numbers (e.g., Stripe test card numbers), example.com for emails, and fictitious numbers for phone and My Number.
