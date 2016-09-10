NAME=saml2aws
ARCH=$(shell uname -m)
VERSION=1.0.0
ITERATION := 1

build:
	rm -rf build && mkdir build
	mkdir -p build/Linux  && GOOS=linux  go build -ldflags "-X main.Version=$(VERSION)" -o build/Linux/$(NAME) ./cmd/$(NAME)
	mkdir -p build/Darwin && GOOS=darwin go build -ldflags "-X main.Version=$(VERSION)" -o build/Darwin/$(NAME) ./cmd/$(NAME)
	mkdir -p build/Darwin && GOOS=windows go build -ldflags "-X main.Version=$(VERSION)" -o build/Windows/$(NAME).exe ./cmd/$(NAME)

test:
	go test -v ./...

.PHONY: build test release packages
