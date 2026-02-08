.PHONY: test clean lint benchmark tools help

APP         = sensitive
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
	$(GO_INSTALL) github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	$(GO_INSTALL) github.com/k1LoW/octocov@latest

lint: ## Lint code
	golangci-lint run --config .golangci.yml

benchmark: ## Run benchmark tests
	$(GO_TEST) -bench=. -benchmem $(GO_PKGROOT) -run=^$$

.DEFAULT_GOAL := help
help:
	@grep -E '^[0-9a-zA-Z_-]+[[:blank:]]*:.*?## .*$$' $(MAKEFILE_LIST) | sort \
	| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[1;32m%-15s\033[0m %s\n", $$1, $$2}'
