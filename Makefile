.PHONY: test clean lint benchmark tools help

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

clean: ## Clean project
	-rm -rf $(APP) cover.*

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

.PHONY: arch race properties mutation fuzz
arch: ## Check production package boundaries
	go run github.com/fe3dback/go-arch-lint@v1.19.0 check
race: ## Run race detection in both modules
	go test -race ./...
	go -C tests test -race ./...
properties: ## Run property and API contract tests
	go -C tests test ./...
mutation: ## Mutate root module packages with gremlins
	go run github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0 unleash --workers 4 --timeout-coefficient 100 .
fuzz: ## Smoke test every root fuzz target
	go test -run '^$$' -fuzz '^FuzzScanner$$' -fuzztime=10s .
	go test -run '^$$' -fuzz '^FuzzScanLines$$' -fuzztime=10s .
	go test -run '^$$' -fuzz '^FuzzMask$$' -fuzztime=10s .
	go test -run '^$$' -fuzz '^FuzzInput$$' -fuzztime=10s .

	go test -run '^$$' -fuzz '^FuzzCanary$$' -fuzztime=10s ./embargotest
	go test -run '^$$' -fuzz '^FuzzJSONStream$$' -fuzztime=10s ./embargotest

.PHONY: compatibility-doc
compatibility-doc: ## Regenerate the table from real output tests
	UPDATE_DOCS=1 go -C tests test -run '^TestCompatibilityTable$$' -count=1 .

.PHONY: accuracy accuracy-doc
accuracy accuracy-doc: ## Regenerate precision and recall from the labeled corpus
	UPDATE_DOCS=1 go -C tests test -run '^TestAccuracyTable$$' -count=1 .

.PHONY: benchmark-doc
benchmark-doc: ## Run and publish reproducible benchmark samples
	python3 scripts/benchmark_docs.py

DOC_MUTATION_TIMEOUT ?= 100

.PHONY: testing-doc
testing-doc: ## Publish completed measurement logs (DOC_COVERAGE, DOC_MUTATION, DOC_FUZZ, DOC_COMMIT)
	python3 scripts/testing_docs.py --coverage "$(DOC_COVERAGE)" --mutation "$(DOC_MUTATION)" --fuzz "$(DOC_FUZZ)" --commit "$(DOC_COMMIT)" --mutation-timeout-coefficient "$(DOC_MUTATION_TIMEOUT)"

.PHONY: doc-figures
doc-figures: ## Regenerate figures from measured data
	python3 scripts/doc_figures.py

.PHONY: masking-doc
masking-doc: ## Regenerate masking views from runnable Examples
	UPDATE_DOCS=1 go test . -run '^TestReadmeMaskingFigure$$' -count=1
