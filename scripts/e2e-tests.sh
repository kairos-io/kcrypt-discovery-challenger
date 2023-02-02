#!/bin/bash

set -e

# This scripts prepares a cluster that runs the challenger server compiled
# from the current checkout.

GINKGO_NODES="${GINKGO_NODES:-1}"

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
CLUSTER_NAME=$(echo $RANDOM | md5sum | head -c 10; echo;)
KUBECONFIG=$(mktemp)

# https://unix.stackexchange.com/a/423052
getFreePort() {
  echo $(comm -23 <(seq "30000" "30200" | sort) <(ss -Htan | awk '{print $4}' | cut -d':' -f2 | sort -u) | shuf | head -n "1")
}

cleanup() {
  echo "Cleaning up $CLUSTER_NAME"
  k3d cluster delete "$CLUSTER_NAME" || true
  rm -rf "$KUBECONFIG"

  # Stop the challenger server
  kill $KMS_PID
}
trap cleanup EXIT

# Create a cluster
k3d cluster create "$CLUSTER_NAME" --image rancher/k3s:v1.26.1-k3s1
k3d kubeconfig get "$CLUSTER_NAME" > "$KUBECONFIG"

# Install cert manager
kubectl apply -f https://github.com/jetstack/cert-manager/releases/latest/download/cert-manager.yaml

# Install the CRDs
kubectl apply -k "$SCRIPT_DIR/../config/crd/"

# Start the challenger server locally
CHALLENGER_PORT=$(getFreePort)
METRICS_PORT=$(getFreePort)
HEALTH_PROBE_PORT=$(getFreePort)
go run "${SCRIPT_DIR}/../" \
  --challenger-bind-address "0.0.0.0:${CHALLENGER_PORT}" \
  --metrics-bind-address "0.0.0.0:${METRICS_PORT}" \
  --health-probe-bind-address "0.0.0.0:${HEALTH_PROBE_PORT}" \
  --namespace default > /dev/null 2>&1 &
export KMS_PID=$!

# 10.0.2.2 is where the vm sees the host
# https://stackoverflow.com/a/6752280
export KMS_ADDRESS="10.0.2.2:${CHALLENGER_PORT}"

PATH=$PATH:$GOPATH/bin ginkgo --nodes $GINKGO_NODES --fail-fast -r ./tests/
