PWD=$(shell pwd)

GO_MODCACHE=$(shell go env GOMODCACHE)

BPF_BUILD_TAG?=build-bpf
GO_BUILD_TAG?=build-go

DOCKER_NOCACHE?=
DOCKER_QUIET?=-q

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
	@docker run --rm -it -v $(PWD)/bpf:/src $(BPF_BUILD_TAG)
.PHONY: build-bpf

# Clean eBPF elf modules
clean-bpf:
	@echo "==> Cleaning eBPF"
	@rm -rf bpf/dist
.PHONY: clean-bpf

# Build the commands
build:
	@find ./cmd/* -maxdepth 1 -type d -exec go build {} \;
.PHONY: build

build-docker: go-build-image
	@echo "==> Building Go binaries"
	@CGO_ENABLED=1 docker run --rm -it \
		-v $(PWD):/app \
		-v $(GO_MODCACHE):/go/pkg/mod \
		$(GO_BUILD_TAG)
.PHONY: build-docker