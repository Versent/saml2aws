NAME=saml2aws
ARCH=$(shell uname -m)
VERSION=2.28.5
ITERATION := 1

GOLANGCI_VERSION = 1.39.0
GORELEASER_VERSION = 0.162.0

SOURCE_FILES?=$$(go list ./... | grep -v /vendor/)
TEST_PATTERN?=.
TEST_OPTIONS?=

BIN_DIR := $(CURDIR)/bin
UNAME := $(shell uname 2>/dev/null || echo Unknown)
GORELEASER_CMD := $(BIN_DIR)/goreleaser build --snapshot --rm-dist

ifeq ($(UNAME),Linux)
	BFLAGS := -tags=hidraw
	GORELEASER_CMD_LINUX := $(GORELEASER_CMD) --config .goreleaser-linux.yml
endif

$(BIN_DIR)/golangci-lint: $(BIN_DIR)/golangci-lint-${GOLANGCI_VERSION}
	@ln -sf golangci-lint-${GOLANGCI_VERSION} $(BIN_DIR)/golangci-lint
$(BIN_DIR)/golangci-lint-${GOLANGCI_VERSION}:
	@curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | BINARY=golangci-lint bash -s -- v${GOLANGCI_VERSION}
	@mv $(BIN_DIR)/golangci-lint $@

$(BIN_DIR)/goreleaser: $(BIN_DIR)/goreleaser-${GORELEASER_VERSION}
	@ln -sf goreleaser-${GORELEASER_VERSION} $(BIN_DIR)/goreleaser
$(BIN_DIR)/goreleaser-${GORELEASER_VERSION}:
	@curl -sfL https://install.goreleaser.com/github.com/goreleaser/goreleaser.sh | BINARY=goreleaser bash -s -- v${GORELEASER_VERSION}
	@mv $(BIN_DIR)/goreleaser $@

mod:
	@go mod download
	@go mod tidy
.PHONY: mod

lint: $(BIN_DIR)/golangci-lint
	@echo "--- lint all the things"
	@$(BIN_DIR)/golangci-lint run ./...
.PHONY: lint

lint-fix: $(BIN_DIR)/golangci-lint
	@echo "--- lint all the things"
	@$(BIN_DIR)/golangci-lint run --fix ./...
.PHONY: lint-fix

fmt: lint-fix

install: mod
	go install $(BFLAGS) -ldflags "-X main.Version=$(VERSION)" ./cmd/saml2aws

build: mod $(BIN_DIR)/goreleaser
	$(GORELEASER_CMD) --config .goreleaser-non-linux.yml
	$(GORELEASER_CMD_LINUX)
.PHONY: build

clean:
	@rm -fr ./dist
.PHONY: clean

generate-mocks:
	mockery -dir pkg/prompter --all
	mockery -dir pkg/provider/okta -name U2FDevice
.PHONY: generate-mocks

test:
	@echo "--- test all the things"
	@go test -cover ./...
.PHONY: test
