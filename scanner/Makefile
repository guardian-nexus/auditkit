# Path: Makefile
.PHONY: help build test scan scan-soc2 scan-pci clean

help:
	@echo "AuditKit Commands:"
	@echo "  make build      - Build binary"
	@echo "  make test       - Run tests"
	@echo "  make scan       - Test scan (CMMC)"
	@echo "  make scan-soc2  - Test scan (SOC2)"
	@echo "  make scan-pci   - Test scan (PCI-DSS)"
	@echo "  make clean      - Clean artifacts"

build:
	@go build -o auditkit ./cmd/auditkit

test:
	@go test ./... -v

scan: build
	@./auditkit scan -provider aws -framework cmmc -verbose

scan-soc2: build
	@./auditkit scan -provider aws -framework soc2 -verbose

scan-pci: build
	@./auditkit scan -provider aws -framework pci -verbose

clean:
	@rm -f auditkit *.pdf *.html *.json

fmt:
	@echo "Formatting code..."
	@goimports -w .
	@go mod tidy

lint:
	@echo "Running linter..."
	@golangci-lint run
