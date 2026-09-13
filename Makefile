BINARY = flat
ARCHS = amd64 arm64
LDFLAGS = -ldflags "-s -w"


.PHONY: all
all: generate build


.PHONY: generate
generate:
	go generate ./...


.PHONY: build
build:
	go build $(LDFLAGS) -o $(BINARY) cmd/flat.go


# Builds flat_linux_<arch>.tar.gz for each arch, plus checksums.txt
.PHONY: release
release: clean generate
	@for arch in $(ARCHS); do \
		echo "Building $$arch..."; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build $(LDFLAGS) -o $(BINARY) cmd/flat.go && \
		tar -czf $(BINARY)_linux_$$arch.tar.gz $(BINARY) || exit 1; \
	done
	@rm -f $(BINARY)
	sha256sum $(BINARY)_linux_*.tar.gz | tee checksums.txt


.PHONY: clean
clean:
	@rm -f $(BINARY) $(BINARY)_linux_*.tar.gz checksums.txt
