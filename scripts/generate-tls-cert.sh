#!/usr/bin/env bash

if [ ! -z "$BASH_VERSION" ]; then
    set -o errexit
    set -o nounset
    set -o pipefail
fi

if [ -v BASH_SOURCE ]; then
    REPO_ROOT=$(dirname "${BASH_SOURCE[0]}")/..
elif [ -n "${0:-}" ]; then
    REPO_ROOT=$(dirname "${0}")
else
    REPO_ROOT=$(pwd)
fi

echo "#### REPO_ROOT ${REPO_ROOT}"

cd "${REPO_ROOT}" || exit 1
NAMESPACE=${NAMESPACE:-gatekeeper-valint}

generate() {
    # generate CA key and certificate
    echo "Generating CA key and certificate for gatekeeper-valint..."
    openssl genrsa -out ca.key 2048
    openssl req -new -x509 -days 356 -key ca.key -subj "/O=Gatekeeper/CN=Gatekeeper Root CA" -out ca.crt

    # generate server key and certificate
    echo "Generating server key and certificate for gatekeeper-valint..."
    openssl genrsa -out tls.key 2048
    openssl req -newkey rsa:2048 -nodes -keyout tls.key -subj "/CN=gatekeeper-valint.${NAMESPACE}" -out server.csr
    openssl x509 -req -extfile <(printf "subjectAltName=DNS:gatekeeper-valint.%s" "${NAMESPACE}") -days 356 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out tls.crt

    echo "Generating signing key and certificate for signed evidence..."
    openssl genrsa -out evidence.key 2048
    openssl req -newkey rsa:2048 -nodes -keyout evidence.key -subj "/CN=gatekeeper-valint.${NAMESPACE}" -out evidence.csr
    openssl x509 -req -extfile <(printf "subjectAltName=DNS:gatekeeper-valint.%s" "${NAMESPACE}") -days 356 -in evidence.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out evidence.crt
}

mkdir -p "${REPO_ROOT}/certs"
pushd "${REPO_ROOT}/certs"
generate
popd

echo "Certificates pushed to $(readlink -f "${REPO_ROOT}/certs")"
