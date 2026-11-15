# Testing

The root suite combines specification vectors and generated examples, metamorphic checks, Go fuzzing with an embedded-secret oracle, negative and labeled recall corpora, reviewed golden logs, and runnable Go examples. The [test-only module](../tests/README.md) documents rapid generators, automatic shrinking, the independent checksum oracles, and periodic gremlins mutation measurements.

Run from the repository root:

```sh
go test ./...
go vet ./...
golangci-lint run
(cd tests && go test ./... && go vet ./... && golangci-lint run --config ../.golangci.yml)
```

Explore new inputs with `go test . -fuzz=FuzzScanner -fuzztime=2m` and measure performance with `make benchmark`. Review API changes before accepting `UPDATE_API=1 go -C tests test ./contracts`. `make test` generates coverage reports and `make lint` runs the root linter.

README Go blocks carry an `example: file:function` marker. `TestReadmeExamples` compares each block to its runnable example, including expected output; update both together. `TestExamplesAppearInGodoc` checks that Go's documentation parser requires a recognized nonempty Output for every exported runtime identifier, including constants and interface methods.
