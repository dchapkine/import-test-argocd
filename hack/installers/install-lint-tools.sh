#!/bin/bash
set -eux -o pipefail

# renovate: datasource=go packageName=github.com/golangci/golangci-lint
GOLANGCI_LINT_VERSION=v1.61.0

GO111MODULE=on go install "github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}"
