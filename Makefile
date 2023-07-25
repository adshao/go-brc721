PROJECT=github.com/adshao/go-brc721

GOHOSTOS:=$(shell go env GOHOSTOS)
GOPATH:=$(shell go env GOPATH)
VERSION=$(shell git describe --tags --always)

PACKAGE_LIST        := go list ./... | grep -vE "vendor"
PACKAGES            := $$($(PACKAGE_LIST))
PACKAGE_DIRECTORIES := $(PACKAGE_LIST) | sed 's|$(PROJECT)/||'
FILES               := $$(find $$($(PACKAGE_DIRECTORIES)) -name "*.go")

GOOS    := $(if $(GOOS),$(GOOS),$(shell go env GOOS))
GOARCH  := $(if $(GOARCH),$(GOARCH),$(shell go env GOARCH))
GOENV   := GO111MODULE=on CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH)
GO      := $(GOENV) go
GOBUILD := $(GO) build $(BUILD_FLAGS)
GOTEST  := $(GO)

FAIL_ON_STDOUT := awk '{ print } END { if (NR > 0) { exit 1 } }'

.PHONY: test unit-test check fmt vet
test: unit-test

unit-test:
	$(GOTEST) test ./... -covermode=count -coverprofile=coverage.out

check: fmt vet

fmt:
	@echo "gofmt (simplify)"
	@gofmt -s -l -w $(FILES) 2>&1 | $(FAIL_ON_STDOUT)

vet:
	$(GO) vet ./...

# show help
help:
	@echo ''
	@echo 'Usage:'
	@echo ' make [target]'
	@echo ''
	@echo 'Targets:'
	@awk '/^[a-zA-Z\-\_0-9]+:/ { \
	helpMessage = match(lastLine, /^# (.*)/); \
		if (helpMessage) { \
			helpCommand = substr($$1, 0, index($$1, ":")-1); \
			helpMessage = substr(lastLine, RSTART + 2, RLENGTH); \
			printf "\033[36m%-22s\033[0m %s\n", helpCommand,helpMessage; \
		} \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help
