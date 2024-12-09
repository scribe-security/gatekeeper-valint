#!/bin/bash
set -x

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 RELEASE_NAME NAMESPACE [CONFIGURATION]"
    exit 1
fi

NAME="$1"
NAMESPACE="$2"
SIGNTYPE="$3"
CERTS_PATH="certs"

# Check if Helm release is already installed
if helm status "$NAME" -n "$NAMESPACE" > /dev/null 2>&1; then
   echo "Already installed. Skipping installation."
else
   # Install Helm release
   kubectl apply -f charts/gatekeeper-valint/crds/template.yaml
   helm install ./charts/gatekeeper-valint --name-template="$NAME" \
      --namespace "$NAMESPACE" --create-namespace \
      --set "certs.caBundle=$(cat $CERTS_PATH/ca.crt | base64 | tr -d '\n')" \
      --set "certs.tlsCrt=$(cat $CERTS_PATH/tls.crt)" \
      --set "certs.tlsKey=$(cat $CERTS_PATH/tls.key)" \
      --set "scribe.enable=true" \
      --set "scribe.client_secret=$SCRIBE_TOKEN" \
      --set "scribe.url=$SCRIBE_URL" \
      --set "image.bundlePullSecrets=$BUNDLE_PULL_SECRET" \
      --set "image.imagePullSecrets=$(cat ~/.docker/config.json | base64 | tr -d '\n')"
      
fi

# Upgrade Helm release
case "$SIGNTYPE" in
  x509)
    VALUES_FILE="values_x509.yaml"
   helm upgrade "$NAME" ./charts/"$NAME" \
      --debug --reuse-values --force \
      --namespace "$NAMESPACE" \
      --set "x509.cert=$(cat $CERTS_PATH/evidence.crt)" \
      --set "x509.key=$(cat $CERTS_PATH/evidence.key)" \
      --set "x509.ca=$(cat $CERTS_PATH/ca.crt)" \
      --values ./charts/"$NAME"/values/"$VALUES_FILE"
    ;;
  sigstore)
    VALUES_FILE="values_sigstore.yaml"
    helm upgrade "$NAME" ./charts/"$NAME" \
      --debug --reuse-values --force \
      --namespace "$NAMESPACE" \
      --values ./charts/"$NAME"/values/"$VALUES_FILE"
    ;;
  *)
    echo "Using default"
    VALUES_FILE="values_default.yaml"
    helm upgrade "$NAME" ./charts/"$NAME" \
      --debug --reuse-values --force \
      --namespace "$NAMESPACE" \
      --values ./charts/"$NAME"/values/"$VALUES_FILE"
    ;;
esac
