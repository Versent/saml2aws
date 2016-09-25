NAME=saml2aws
ARCH=$(shell uname -m)
VERSION=1.2.0
ITERATION := 1

default: build

deps:
	go install golang.org/x/tools/cmd/stringer
	glide install

generate:
	go generate

build: deps generate
	rm -rf build && mkdir build
	mkdir -p build/Linux  && GOOS=linux  go build -ldflags "-X main.Version=$(VERSION)" -o build/Linux/$(NAME) ./cmd/$(NAME)
	mkdir -p build/Darwin && GOOS=darwin go build -ldflags "-X main.Version=$(VERSION)" -o build/Darwin/$(NAME) ./cmd/$(NAME)
	mkdir -p build/Windows && GOOS=windows go build -ldflags "-X main.Version=$(VERSION)" -o build/Windows/$(NAME).exe ./cmd/$(NAME)

release: build
	rm -rf release && mkdir release
	tar -zcf release/$(NAME)_$(VERSION)_linux_$(ARCH).tgz -C build/Linux $(NAME)
	tar -zcf release/$(NAME)_$(VERSION)_darwin_$(ARCH).tgz -C build/Darwin $(NAME)
	tar -zcf release/$(NAME)_$(VERSION)_windows_$(ARCH).tgz -C build/Windows $(NAME).exe
	gh-release create versent/$(NAME) $(VERSION) $(shell git rev-parse --abbrev-ref HEAD)

test:
	go test -cover -v $(shell glide novendor)

.PHONY: default deps generate build test release packages
