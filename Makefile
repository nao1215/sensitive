.PHONY: build release-snapshot test clean lint benchmark tools help

export GOMAXPROCS := 4

APP         = embargo
GO          = go
GO_BUILD    = $(GO) build
GO_FORMAT   = $(GO) fmt
GO_LIST     = $(GO) list
GO_TEST     = $(GO) test
GO_TOOL     = $(GO) tool
GO_VET      = $(GO) vet
GO_INSTALL  = $(GO) install
GO_PKGROOT  = ./...
GO_PACKAGES = $(shell $(GO_LIST) $(GO_PKGROOT))

build: ## Build the embargo command into the repository root
	$(GO_BUILD) -trimpath -o $(APP) ./cmd/embargo

release-snapshot: ## Build every release archive locally without publishing
	GORELEASER_CURRENT_TAG=$$(git describe --tags --abbrev=0 --match 'v*') goreleaser release --snapshot --clean --skip=sign,sbom,publish
	sh scripts/smoke_artifacts.sh

clean: ## Clean project
	-rm -rf $(APP) cover.* dist

test: ## Run tests with coverage
	$(GO_TEST) -cover $(GO_PKGROOT) -coverpkg=./... -coverprofile=cover.out
	$(GO_TOOL) cover -html=cover.out -o cover.html

tools: ## Install dependency tools
	$(GO_INSTALL) github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
	$(GO_INSTALL) github.com/k1LoW/octocov@latest

lint: ## Lint code
	golangci-lint run --config .golangci.yml

benchmark: ## Run benchmark tests
	$(GO_TEST) -bench=. -benchmem $(GO_PKGROOT) -run=^$$

.DEFAULT_GOAL := help
help:
	@grep -E '^[0-9a-zA-Z_-]+[[:blank:]]*:.*?## .*$$' $(MAKEFILE_LIST) | sort \
	| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[1;32m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: arch race properties mutation mutation-diff fuzz
arch: ## Check production package boundaries
	go run github.com/fe3dback/go-arch-lint@v1.19.0 check
race: ## Run race detection in all modules
	go test -race ./...
	go -C tests test -race ./...
	@for module in zap zerolog logrus grpc otel sentry; do go -C adapters/$$module test -race ./... || exit; done
properties: ## Run property and API contract tests
	go -C tests test ./...
# Two CPUs per mutation worker, at most eight workers (two on a 4-CPU runner).
MUTATION_WORKERS ?= $(shell python3 -c 'import os; print(min(8, max(1, os.cpu_count()//2)))')
mutation: ## Mutate root module packages with gremlins
	python3 scripts/mutation_gate.py --workers $(MUTATION_WORKERS) --test-cpu 2
BASE ?= origin/main
mutation-diff: ## Mutate lines changed since BASE and list survivors
	python3 scripts/mutation_gate.py --workers $(MUTATION_WORKERS) --test-cpu 2 --diff $(BASE)
fuzz: ## Smoke test every root fuzz target
	python3 scripts/fuzz_targets.py --run 10s


.PHONY: test-e2e
test-e2e: ## Run the atago end-to-end specs against the embargo command
	./scripts/run_e2e.sh

.PHONY: compatibility-doc
compatibility-doc: ## Regenerate the table from real output tests
	UPDATE_DOCS=1 go -C tests test -run '^TestCompatibilityTable$$' -count=1 .

.PHONY: accuracy accuracy-doc
accuracy accuracy-doc: credential-accuracy ## Regenerate precision and recall from the labeled corpus
	python3 scripts/generate_accuracy.py
	UPDATE_DOCS=1 go -C tests test -run '^Test(AccuracyTable|SeverityAccuracy|DefaultThresholdAccuracy)$$' -count=1 .
	python3 scripts/accuracy_figures.py

.PHONY: benchmark-doc
benchmark-doc: ## Run and publish reproducible benchmark samples
	python3 scripts/benchmark_docs.py

DOC_MUTATION_TIMEOUT ?= 10

.PHONY: testing-doc
testing-doc: ## Publish completed measurement logs (DOC_COVERAGE, DOC_MUTATION, DOC_FUZZ, DOC_COMMIT)
	python3 scripts/testing_docs.py --coverage "$(DOC_COVERAGE)" --mutation "$(DOC_MUTATION)" --fuzz "$(DOC_FUZZ)" --mutation-timeout-coefficient "$(DOC_MUTATION_TIMEOUT)"

.PHONY: doc-figures
doc-figures: ## Regenerate figures from measured data
	python3 scripts/doc_figures.py

.PHONY: masking-doc
masking-doc: ## Regenerate masking views from runnable Examples
	UPDATE_DOCS=1 go test . -run '^TestReadmeMaskingFigure$$' -count=1

.PHONY: adapters
adapters: ## Test all optional logger modules
	@for module in zap zerolog logrus grpc otel sentry; do go -C adapters/$$module test ./... || exit; done

.PHONY: comparison-doc
comparison-doc: ## Measure masking libraries and regenerate comparison tables and chart
	python3 scripts/comparison_docs.py --measure

.PHONY: leak-scenarios credential-accuracy
leak-scenarios: ## Regenerate realistic service leak comparisons
	UPDATE_DOCS=1 go -C tests test -run '^TestLeakScenarios$$' -count=1 .
credential-accuracy: ## Regenerate independent credential precision and recall
	python3 scripts/generate_credentials.py --check
	UPDATE_DOCS=1 go -C tests test -run '^TestCredentialAccuracy$$' -count=1 .

LOG_CACHE ?= $(HOME)/.cache/embargo-real-logs
.PHONY: real-log-accuracy
real-log-accuracy: ## Scan checksum-pinned public logs cached outside the repository
	python3 scripts/real_logs.py --measure --cache "$(LOG_CACHE)"

CPU ?= 0
.PHONY: scanner-experiment
scanner-experiment: ## Repeat the rejected lexer and kind-selection benchmarks (BASE clone, CPU)
	@test -n "$(strip $(BASE))" || { echo 'BASE must name a baseline clone' >&2; exit 1; }
	python3 scripts/scanner_experiment.py --measure --cpu "$(CPU)"
