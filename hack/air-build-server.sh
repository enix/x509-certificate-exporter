#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

export CGO_ENABLED=0
export GO111MODULE=on
export GOFLAGS="-mod=vendor"

MODULE=$(go list -m)

LDFLAGS=()
LDFLAGS+=" -X ${MODULE}/internal/internal.Version=$(git describe --tags --always --dirty)"
LDFLAGS+=" -X ${MODULE}/internal/internal.BuildDateTime=$(date --iso-8601=seconds)"
LDFLAGS+=" -X ${MODULE}/internal/internal.Revision=$(git rev-parse HEAD)"

go build \
    -ldflags "${LDFLAGS[*]}" \
    -o ./tmp/x509-certificate-exporter \
    ./cmd/x509-certificate-exporter
