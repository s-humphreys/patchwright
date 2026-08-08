.PHONY: help deps build test test-integration vet fmt tidy check run-profile run-assess

GOBIN := $(shell go env GOPATH)/bin

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

deps: ## Install dev tools required for integration tests (kind, ginkgo)
	go install sigs.k8s.io/kind@latest
	go install github.com/onsi/ginkgo/v2/ginkgo@latest
	@echo "Installed kind and ginkgo to $(GOBIN)."
	@echo "Ensure it is on your PATH:  export PATH=\"$(GOBIN):\$$PATH\""
	@command -v kubectl >/dev/null 2>&1 || echo "NOTE: kubectl not found — install it to run integration tests."

build: ## Build all packages
	go build ./...

test: ## Run unit + golden tests (no cluster required)
	go test ./...

test-integration: ## Run the kind-based e2e suite (requires docker + kind)
	PATH="$(GOBIN):$$PATH" go test -tags e2e -timeout 20m -v ./test/e2e/...

vet: ## Vet all packages (including the e2e-tagged suite)
	go vet ./...
	go vet -tags e2e ./...

fmt: ## Format the tree
	gofmt -w .

tidy: ## Tidy module dependencies
	go mod tidy

check: fmt vet test ## Format, vet, and test

# Convenience targets for local exploration against a sample export.
# Override with: make run-assess INPUT=your-export.csv
INPUT ?= testdata/sample.csv

run-profile: ## Profile an export (INPUT=path)
	go run ./cmd/patchwright profile -i $(INPUT)

run-assess: ## Assess an export (INPUT=path)
	go run ./cmd/patchwright assess -i $(INPUT) -c config/

report: build ## Assess your real export in local/ (auto-detects CSV + local/config); pass ARGS='--format json'
	@csv="$${CSV:-$$(ls local/*.csv 2>/dev/null | head -1)}"; \
	cfg="$${CONFIG:-$$(test -d local/config && echo local/config || echo config)}"; \
	if [ -z "$$csv" ]; then echo "No CSV found in local/. Put your export there, or pass CSV=path/to.csv"; exit 1; fi; \
	echo "» export: $$csv"; echo "» config: $$cfg"; echo; \
	./bin/patchwright assess -i "$$csv" -c "$$cfg" $(ARGS)
