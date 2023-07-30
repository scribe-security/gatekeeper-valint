# valint-gatekeeper-provider
To integrate [OPA Gatekeeper's ExternalData feature](https://open-policy-agent.github.io/gatekeeper/website/docs/externaldata) with [valint](https://github.com/scribe-security/valint).

> This repo is meant for testing Gatekeeper external data feature. Do not use for production.

## Installation

- Deploy Gatekeeper with external data enabled (`--enable-external-data`)
```sh
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm install gatekeeper/gatekeeper  \
    --name-template=gatekeeper \
    --namespace gatekeeper-system --create-namespace \
    --set enableExternalData=true \
    --set controllerManager.dnsPolicy=ClusterFirst,audit.dnsPolicy=ClusterFirst
```

Let's install the `valint-gatekeeper-provider`:

- `kubectl apply -f manifest`

- `kubectl apply -f manifest/provider.yaml`
  > Update `url` if it's not `http://valint-gatekeeper-provider.valint-gatekeeper-provider:8090` (default)

- `kubectl apply -f policy/template.yaml`

- `kubectl apply -f policy/constraint.yaml`
