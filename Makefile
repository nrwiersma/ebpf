PWD=$(shell pwd)

CGO_ENABLED=0
GO_MODCACHE=$(shell go env GOMODCACHE)
GO_BUILDCACHE=$(shell go env GOCACHE)

BPF_BUILD_TAG?=build-bpf
GO_BUILD_TAG?=build-go

DOCKER_IMAGE?=ebpf:latest
DOCKER_NOCACHE?=
DOCKER_QUIET?=-q

export CGO_ENABLED

# Format all files
fmt:
	@echo "==> Formatting source"
	@gofmt -s -w $(shell find . -type f -name '*.go' -not -path "./vendor/*")
	@echo "==> Done"
.PHONY: fmt

# Tidy the go.mod file
tidy:
	@echo "==> Cleaning go.mod"
	@go mod tidy
	@echo "==> Done"
.PHONY: tidy

# Lint the project
lint:
	@golangci-lint run ./...
.PHONY: lint

lint-docker: go-build-image
	@docker run --rm -it \
		-v $(PWD):/app \
		-v $(GO_MODCACHE):/go/pkg/mod:cached \
		-v $(GO_BUILDCACHE):/root/.cache/go-build:cached \
		-v $(PWD)/.cache/golangci-lint:/root/.cache/golangci-lint:cached \
		$(GO_BUILD_TAG) \
		make lint
.PHONY: lint-docker

# Build the bpf build docker image
bpf-build-image:
	@echo "==> Building eBPF build container"
	@docker build $(DOCKER_NOCACHE) $(DOCKER_QUIET) -t $(BPF_BUILD_TAG) - <.build/docker/build-bpf.dockerfile
.PHONY: bpf-build-image

# Build the go build docker image
go-build-image:
	@echo "==> Building Go build container"
	@docker build $(DOCKER_NOCACHE) $(DOCKER_QUIET) -t $(GO_BUILD_TAG) - <.build/docker/build-go.dockerfile
.PHONY: go-build-image

# Build eBPF elf modules
build-bpf: bpf-build-image clean-bpf
	@echo "==> Building eBPF elf"
	@docker run --rm -it -v $(PWD)/bpf:/bpf $(BPF_BUILD_TAG) build
.PHONY: build-bpf

# Build eBPF elf modules
build-bpf-asm: bpf-build-image clean-bpf
	@echo "==> Building/Dumping eBPF elf"
	@docker run --rm -it -v $(PWD)/bpf:/bpf $(BPF_BUILD_TAG) dump
.PHONY: build-bpf-asm

# Clean eBPF elf modules
clean-bpf:
	@echo "==> Cleaning eBPF"
	@rm -rf bpf/dist
.PHONY: clean-bpf

# Build the commands
build:
	@GOOS=linux GOARCH=amd64 find ./cmd/* -maxdepth 1 -type d -exec go build -ldflags="-w -s" {} \;
.PHONY: build

build-docker: go-build-image
	@echo "==> Building Go binaries"
	@docker run --rm -it \
		-v $(PWD):/app \
		-v $(GO_MODCACHE):/go/pkg/mod:cached \
		-v $(GO_BUILDCACHE):/root/.cache/go-build:cached \
		$(GO_BUILD_TAG)
.PHONY: build-docker

image: build
	@echo "==> Building Docker image"
	@docker build $(DOCKER_NOCACHE) -t $(DOCKER_IMAGE) .
.PHONY: image

push-image:
	@echo "==> Pushing Docker image"
	@docker tag ebpf:latest media-server.wiersma.lan/ebpf:latest
	@docker push media-server.wiersma.lan/ebpf:latest
	@docker rmi media-server.wiersma.lan/ebpf:latest
.PHONY: push-image

# Run all tests
test:
	@go test -cover -race ./...
.PHONY: test
