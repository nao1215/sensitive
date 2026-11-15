# Contributing Guide

## Introduction

Contributions can add features, fix bugs, improve documentation or test a missing failure path. Run the checks below before opening a pull request.

## Setting Up Development Environment

### Prerequisites

#### Installing Go

See [Installation and requirements](README.md#installation-and-requirements) for the library's Go floor and [Testing](README.md#testing) for the separate test module's requirement. Install a current Go toolchain using the [official installation guide](https://go.dev/doc/install).

Verify installation:
```bash
go version
```

### Cloning the Project

```bash
git clone https://github.com/nao1215/embargo.git
cd embargo
```

### Installing Development Tools

```bash
# Install necessary development tools
make tools
```

### Verification

To verify that your development environment is set up correctly, run the following commands:

```bash
# Run tests
make test

# Run linter
make lint

# Run the separate property tests
(cd tests && go test ./...)
```

## Development Workflow

### Branch Strategy

- `main` branch is the latest stable version
- Create new branches from `main` for new features or bug fixes
- Branch naming examples:
  - `feature/add-detector-x` - New feature
  - `fix/issue-123` - Bug fix
  - `docs/update-readme` - Documentation update

### Coding Standards

This project follows these standards:

1. Conform to Effective Go
2. Avoid using global variables
3. Always add comments to public functions, variables, and structs
4. Keep functions as small as possible
5. Writing tests is encouraged

### Writing Tests

Tests are important. Please follow these guidelines:

1. Unit tests: Aim for 97% or higher coverage
2. Test readability: Write clear test cases
3. Parallel execution: Use `t.Parallel()` whenever possible

### Adding New Detectors

When adding a new detector:

1. Add the detector implementation under `internal/detect/`
2. Add the option in `option.go`
3. Add tests in `internal/detect/*_test.go`
4. Update the README with the new detector documentation

## Using AI Assistants (LLMs)

We actively encourage the use of AI coding assistants to improve productivity and code quality. Tools like Claude Code, GitHub Copilot, and Cursor are welcome for:

- Writing boilerplate code
- Generating tests for failure paths
- Improving documentation
- Refactoring existing code
- Finding potential bugs
- Suggesting performance optimizations
- Translating documentation

### Guidelines for AI-Assisted Development

1. Review all generated code: Always review and understand AI-generated code before committing
2. Maintain consistency: Ensure AI-generated code follows our coding standards in CLAUDE.md
3. Test thoroughly: AI-generated code must pass all tests and linting (`make test` and `make lint`)
4. Use project configuration: We provide `CLAUDE.md` to help AI assistants understand our project standards

## Creating Pull Requests

### Preparation

1. Check or Create Issues
   - Check if there are existing issues
   - For major changes, we recommend discussing the approach in an issue first

2. Write Tests
   - Always add tests for new features
   - For bug fixes, create tests that reproduce the bug
   - AI tools can help generate tests for failure paths

3. Quality Check
   ```bash
   # Ensure all tests pass
   make test

   # Linter check
   make lint

   # Check coverage (97% or higher)
   go test -cover ./...
   ```

### Submitting Pull Request

1. Create a Pull Request from your forked repository to the main repository
2. PR title should briefly describe the changes
3. Include the following in PR description:
   - Purpose and content of changes
   - Related issue number (if any)
   - Test method
   - Reproduction steps for bug fixes

### About CI/CD

GitHub Actions automatically checks the following items:

- Cross-platform testing: Test execution on Linux, macOS, and Windows
- Linter check: Static analysis with golangci-lint
- Test coverage: Maintain 97% or higher coverage
- Build verification: Successful builds on each platform

Merging is not possible unless all checks pass.

## Bug Reports

When you find a bug, please create an issue with the following information:

1. Environment Information
   - OS (Linux/macOS/Windows) and version
   - Go version
   - embargo version

2. Reproduction Steps
   - Minimal code example to reproduce the bug
   - Sample data inputs (if applicable)

3. Expected and Actual Behavior

4. Error Messages or Stack Traces (if any)

## Contributing Outside of Coding

The following activities are also greatly welcomed:

### Activities that Boost Motivation

- Give a GitHub Star: Show your interest in the project
- Promote the Project: Introduce it in blogs, social media, study groups, etc.
- Become a GitHub Sponsor: Support available at https://github.com/sponsors/nao1215

### Other Ways to Contribute

- Documentation Improvements: Fix typos, improve clarity of explanations
- Translations: Translate documentation to new languages
- Add Examples: Provide practical sample code in `example_test.go`
- Feature Suggestions: Share new detector ideas in issues

## Community

### Code of Conduct

Please refer to [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). We expect all contributors to treat each other with respect.

### Questions and Reports

- GitHub Issues: Bug reports and feature suggestions

## License

Contributions to this project are considered to be released under the project's license (MIT License).

---



## Documentation checks

Pull requests and pushes always check README snippets against runnable Examples and validate generated accuracy, benchmark, testing and compatibility tables. The table-only compatibility check skips SDK, HTTP and child-process subtests; those remain in the full code suite. Documentation-only changes (*.md, doc/, LICENSE, .all-contributorsrc and image files) skip the Go matrix, coverage, lint and vulnerability jobs through job conditions. Unrecognized paths, workflow changes and changes to executable tools run the full checks. Rename classification includes both the old and new paths, and missing Git history fails the classifier.

CodeQL still runs on every pull request and main push to retain Scorecard SAST coverage of recent changesets. Nightly fuzz, scheduled Scorecard and scheduled vulnerability scans remain enabled. There is no pull-request mutation workflow; mutation runs weekly and through an explicit make target. Workflow edits also run actionlint, and spelling review stays enabled for documentation. Branch rules had no required status checks when this policy was introduced; job-level conditions keep skipped checks visible instead of preventing workflow creation.
## Prose and policy checks

Run `python3 scripts/check_prose.py`, `python3 scripts/check_policies.py` and `python3 scripts/testing_techniques.py --check` before submission. The prose checker reads README.md, CHANGELOG.md, CONTRIBUTING.md, doc/*.md, exported godoc including struct fields, and runnable Example comments and string literals. Code fences and URLs are excluded from prose matching. Markdown English paragraphs occupy one source line; Go comments retain normal source wrapping.

The banned filler list is `robust`, `seamless`, `comprehensive`, `leverage`, `effortless`, `powerful`, `simply`, and `just`. Stock introductions and conclusions, bold emphasis, emoji and slash-joined benchmark triples also fail. A godoc that merely restates its identifier fails. Within a package, an opening template used by at least eight comments and more than 25% of comments fails; a sentence longer than 70 characters repeated at least three times fails. This catches copy-pasted claims while allowing short interface conventions.

Table cells may contain at most 120 visible characters, approximating two rendered lines in a wide cell at 1280px. Review narrow columns visually. Move explanations below a table instead of abbreviating away limits. Exceptions in scripts/prose_allowlist.json identify exact text by hash and require a reason; unused exceptions fail. Add a negative fixture when adding a rule so a checker that always succeeds cannot pass its own tests.

The [policy inventory](doc/policies.md) maps owner decisions to checks. Regression tests precede production fixes; retain the failing command and result in the round report. Use English Conventional Commit titles without agent trailers. Squash only after current-head CI is green and review threads are resolved; `scripts/check_merge.py` reads those conditions before the owner-authorized merge. Publication and repository security settings remain separate owner actions.
