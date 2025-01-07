#!/bin/bash

# This script should be somewhat idempotent

[ -d hack ] || {
  echo "Run this script from the project root with: ./hack/$(basename $0)" >&2
  exit 1
}

set -xe

. .env

# create the Kind cluster
C="${KIND_NAME:-x509}"
kind create cluster -n "$C" || true
CTX="kind-$C"
K="kubectl --context $CTX"
$K cluster-info

# wait for nodes to be Ready
$K wait --timeout=1h --for=condition=Ready=true node -l node-role.kubernetes.io/control-plane
sleep 2

# get kubeconfig
kind get kubeconfig --name $C > kubeconfig.yaml
