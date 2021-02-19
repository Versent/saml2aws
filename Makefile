NAME=saml2aws
ARCH=$(shell uname -m)
VERSION=2.28.0
ITERATION := 1

GOLANGCI_VERSION = 1.32.0

SOURCE_FILES?=$$(go list ./... | grep -v /vendor/)
TEST_PATTERN?=.
TEST_OPTIONS?=

BIN_DIR := $(CURDIR)/bin

ci: prepare test

$(BIN_DIR)/golangci-lint: $(BIN_DIR)/golangci-lint-${GOLANGCI_VERSION}
	@ln -sf golangci-lint-${GOLANGCI_VERSION} $(BIN_DIR)/golangci-lint
$(BIN_DIR)/golangci-lint-${GOLANGCI_VERSION}:
	@curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | BINARY=golangci-lint bash -s -- v${GOLANGCI_VERSION}
	@mv $(BIN_DIR)/golangci-lint $@

$(BIN_DIR)/goreleaser:
	@go get -u github.com/goreleaser/goreleaser
	@env GOBIN=$(BIN_DIR) GO111MODULE=on go install github.com/goreleaser/goreleaser

mod:
	@go mod download
	@go mod tidy

lint: $(BIN_DIR)/golangci-lint
	@echo "--- lint all the things"
	@$(BIN_DIR)/golangci-lint run ./...
.PHONY: lint

lint-fix: $(BIN_DIR)/golangci-lint
	@echo "--- lint all the things"
	@$(BIN_DIR)/golangci-lint run --fix ./...
.PHONY: lint-fix

fmt: lint-fix

test:
	@$(BIN_DIR)/gocov test $(SOURCE_FILES) | $(BIN_DIR)/gocov report

local-compile: mod
	@rm -rf build/
	@$(BIN_DIR)/gox -ldflags "-X main.Version=$(VERSION)" \
	-osarch="darwin/amd64" \
	-osarch="linux/i386" \
	-osarch="linux/amd64" \
	-osarch="windows/amd64" \
	-osarch="windows/i386" \
	-output "build/{{.Dir}}_$(VERSION)_{{.OS}}_{{.Arch}}/$(NAME)" \
	${SOURCE_FILES}

local-build: lint test local-compile

install:
	go install ./cmd/saml2aws

release-snapshot: $(BIN_DIR)/goreleaser
	$(BIN_DIR)/goreleaser --snapshot --rm-dist

clean:
	@rm -fr ./build

generate-mocks:
	mockery -dir pkg/prompter --all
	mockery -dir pkg/provider/okta -name U2FDevice

.PHONY: default prepare mod compile fmt dist release test clean generate-mocks
