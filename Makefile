BINARY_NAME = flat
BINARY_STANDARD = $(BINARY_NAME)
BINARY_GREENTEAGC = $(BINARY_NAME)-greenteagc


GZIP_STANDARD = $(BINARY_NAME).tar.gz
GZIP_GREENTEAGC = $(BINARY_NAME)-greenteagc.tar.gz


LDFLAGS = -ldflags "-s -w"


.PHONY: all
all: clean generate build package checksums


.PHONY: generate
generate:
	@echo "Running go generate..."
	go generate ./...


.PHONY: build
build: build-standard build-greenteagc


.PHONY: build-standard
build-standard:
	@echo "Building standard binary..."
	go build $(LDFLAGS) -o $(BINARY_STANDARD)


.PHONY: build-greenteagc
build-greenteagc:
	@echo "Building green tea GC binary..."
	GOEXPERIMENT=greenteagc go build $(LDFLAGS) -o $(BINARY_GREENTEAGC)


.PHONY: package
package: package-standard package-greenteagc


.PHONY: package-standard
package-standard:
	@echo "Packaging standard binary..."
	tar -czf $(GZIP_STANDARD) $(BINARY_STANDARD)
	@rm -f $(BINARY_STANDARD)


.PHONY: package-greenteagc
package-greenteagc:
	@echo "Packaging green tea GC binary..."
	tar -czf $(GZIP_GREENTEAGC) $(BINARY_GREENTEAGC)
	@rm -f $(BINARY_GREENTEAGC)


.PHONY: checksums
checksums:
	@echo ""
	@echo "SHA256 Checksums:"
	@echo "================="
	@if [ -f $(GZIP_STANDARD) ]; then \
		echo "Standard version ($(GZIP_STANDARD)):"; \
		sha256sum $(GZIP_STANDARD) || shasum -a 256 $(GZIP_STANDARD); \
	fi
	@if [ -f $(GZIP_GREENTEAGC) ]; then \
		echo "Green Tea GC version ($(GZIP_GREENTEAGC)):"; \
		sha256sum $(GZIP_GREENTEAGC) || shasum -a 256 $(GZIP_GREENTEAGC); \
	fi
	@echo ""


.PHONY: standard
standard: clean generate
	@echo "Building standard binary..."
	go build $(LDFLAGS) -o $(BINARY_NAME)
	@echo "Packaging standard binary..."
	tar -czf $(GZIP_STANDARD) $(BINARY_NAME)
	@rm -f $(BINARY_NAME)
	@echo ""
	@echo "SHA256 Checksum for standard version:"
	@sha256sum $(GZIP_STANDARD) || shasum -a 256 $(GZIP_STANDARD)


.PHONY: greenteagc
greenteagc: clean generate
	@echo "Building green tea GC binary..."
	GOEXPERIMENT=greenteagc go build $(LDFLAGS) -o $(BINARY_NAME)
	@echo "Packaging green tea GC binary..."
	tar -czf $(GZIP_GREENTEAGC) $(BINARY_NAME)
	@rm -f $(BINARY_NAME)
	@echo ""
	@echo "SHA256 Checksum for green tea GC version:"
	@sha256sum $(GZIP_GREENTEAGC) || shasum -a 256 $(GZIP_GREENTEAGC)


.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -f $(BINARY_NAME)
	@rm -f $(GZIP_STANDARD) $(GZIP_GREENTEAGC)


.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all        - Build both versions, package them, and show checksums (default)"
	@echo "  standard   - Build only the standard version"
	@echo "  greenteagc - Build only the green tea GC version"
	@echo "  generate   - Run go generate"
	@echo "  build      - Build both binaries without packaging"
	@echo "  package    - Package existing binaries into gzip files"
	@echo "  checksums  - Display SHA256 checksums of gzip files"
	@echo "  clean      - Remove all build artifacts"
	@echo "  help       - Show this help message"