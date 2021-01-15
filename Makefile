NAME=saml2aws
ARCH=$(shell uname -m)
VERSION=2.28.1
ITERATION := 1

GOLANGCI_VERSION = 1.32.0
GORELEASER_VERSION = 0.157.0

SOURCE_FILES?=$$(go list ./... | grep -v /vendor/)
TEST_PATTERN?=.
TEST_OPTIONS?=

BIN_DIR := $(CURDIR)/bin

LINUX_BUILD_OPS := -tags="hidraw" -osarch="linux/i386" -osarch="linux/amd64"
WINDOWS_BUILD_OPS := -osarch="windows/i386" -osarch="windows/amd64"
DARWIN_BUILD_OPS := -osarch="darwin/amd64"

# Partially based on https://stackoverflow.com/questions/714100/os-detecting-makefile/52062069#52062069
ifeq '$(findstring ;,$(PATH))' ';'
	UNAME := Windows
else
	UNAME := $(shell uname 2>/dev/null || echo Unknown)
endif

ci: prepare test

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

define compile
	@$(BIN_DIR)/gox -ldflags "-X main.Version=$(VERSION)" \
	$(1) \
	-output "build/{{.Dir}}_$(VERSION)_{{.OS}}_{{.Arch}}/$(NAME)" \
	${SOURCE_FILES}
endef

linux: mod
	$(call compile,$(LINUX_BUILD_OPS))

windows: mod
	$(call compile,$(WINDOWS_BUILD_OPS))

darwin: mod
	@if [ "$(UNAME)" = "Darwin" ]; then \
		$(call compile,$(DARWIN_BUILD_OPS)); \
	else \
		echo "\nWARNING: Trying to compile Darwin on a non-Darwin OS\nOS Detected: $(UNAME)"; \
	fi

compile: clean linux windows darwin

lint-fix: $(BIN_DIR)/golangci-lint
	@echo "--- lint all the things"
	@$(BIN_DIR)/golangci-lint run --fix ./...
.PHONY: lint-fix

fmt: lint-fix

install: mod
	go install -ldflags "-X main.Version=$(VERSION)" ./cmd/saml2aws

build: $(BIN_DIR)/goreleaser
	$(BIN_DIR)/goreleaser build --snapshot --rm-dist
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
