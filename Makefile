NAME=saml2aws
ARCH=$(shell uname -m)
OS=$(shell uname)
ITERATION := 1

GOLANGCI_VERSION = 1.45.2
GORELEASER_VERSION = 1.16.2

SOURCE_FILES?=$$(go list ./... | grep -v /vendor/)
TEST_PATTERN?=.
TEST_OPTIONS?=

BIN_DIR := $(CURDIR)/bin

ci: prepare test

$(BIN_DIR)/goreleaser:
	@GOBIN=$(BIN_DIR) go install github.com/goreleaser/goreleaser@v${GORELEASER_VERSION}
.PHONY: $(BIN_DIR)/goreleaser

mod:
	@go mod download
	@go mod tidy
.PHONY: mod

lint: 
	@echo "--- lint all the things"
	@docker run --rm -v $(shell pwd):/app -w /app golangci/golangci-lint:v$(GOLANGCI_VERSION) golangci-lint run -v
.PHONY: lint

lint-fix:
	@echo "--- lint all the things"
	@docker run --rm -v $(shell pwd):/app -w /app golangci/golangci-lint:v$(GOLANGCI_VERSION) golangci-lint run -v --fix
.PHONY: lint-fix

fmt: lint-fix

install:
	go install ./cmd/saml2aws
.PHONY: mod

build: $(BIN_DIR)/goreleaser
ifeq ($(OS),Darwin)
	$(BIN_DIR)/goreleaser build --snapshot --clean --config $(CURDIR)/.goreleaser.macos-latest.yml
else ifeq ($(OS),Linux)
	$(BIN_DIR)/goreleaser build --snapshot --clean --config $(CURDIR)/.goreleaser.ubuntu-latest.yml
else
	$(error Unsupported build OS: $(OS))
endif
.PHONY: build

clean:
	@rm -fr ./build
.PHONY: clean

generate-mocks:
	mockery -dir pkg/prompter --all
	mockery -dir pkg/provider/okta -name U2FDevice
.PHONY: generate-mocks

test:
	@echo "--- test all the things"
	@go test -cover ./...
.PHONY: test
