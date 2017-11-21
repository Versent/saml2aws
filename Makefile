NAME=saml2aws
ARCH=$(shell uname -m)
VERSION=2.0.1
ITERATION := 1

default: deps compile

glide:
ifeq ($(shell uname),Darwin)
	curl -L https://github.com/Masterminds/glide/releases/download/v0.12.3/glide-v0.12.3-darwin-amd64.zip -o glide.zip
	unzip glide.zip
	mv ./darwin-amd64/glide ./glide
	rm -fr ./darwin-amd64
	rm ./glide.zip
else
	curl -L https://github.com/Masterminds/glide/releases/download/v0.12.3/glide-v0.12.3-linux-386.zip -o glide.zip
	unzip glide.zip
	mv ./linux-386/glide ./glide
	rm -fr ./linux-386
	rm ./glide.zip
endif

deps: glide
	# go get github.com/buildkite/github-release
	go get -u github.com/alecthomas/gometalinter	
	go get github.com/mitchellh/gox
	./glide install
	gometalinter --install

compile: deps
	@rm -rf build/
	@gox -ldflags "-X main.Version=$(VERSION)" \
	-osarch="darwin/amd64" \
	-osarch="linux/i386" \
	-osarch="linux/amd64" \
	-osarch="windows/amd64" \
	-osarch="windows/i386" \
	-output "build/{{.Dir}}_$(VERSION)_{{.OS}}_{{.Arch}}/$(NAME)" \
	$(shell ./glide novendor)

# Run all the linters
lint:
	gometalinter --vendor ./...

# gofmt and goimports all go files
fmt:
	find . -name '*.go' -not -wholename './vendor/*' | while read -r file; do gofmt -w -s "$$file"; goimports -w "$$file"; done

install:
	go install ./cmd/saml2aws

dist:
	$(eval FILES := $(shell ls build))
	@rm -rf dist && mkdir dist
	@for f in $(FILES); do \
		(cd $(shell pwd)/build/$$f && tar -cvzf ../../dist/$$f.tar.gz *); \
		(cd $(shell pwd)/dist && shasum -a 512 $$f.tar.gz > $$f.sha512); \
		echo $$f; \
	done

release:
	@github-release "v$(VERSION)" dist/* --commit "$(git rev-parse HEAD)" --github-repository versent/$(NAME)

test: deps
	go test -cover -v $(shell ./glide novendor)

clean:
	rm ./glide
	rm -fr ./build

generate-mocks:
	mockery -dir pkg/prompter --all

.PHONY: default deps compile lint fmt dist release test clean generate-mocks
