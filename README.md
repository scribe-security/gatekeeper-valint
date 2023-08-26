# gatekeeper-valint
To integrate [OPA Gatekeeper's ExternalData feature](https://open-policy-agent.github.io/gatekeeper/website/docs/externaldata) with [Valint](https://github.com/scribe-security/valint) to determine whether the images are valid by verifying its signatures and apply custom policies.

> This repo is meant for testing Gatekeeper external data feature. Do not use for production.

## Installation

- Deploy Gatekeeper with external data enabled (`--enable-external-data`)
```sh
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm install gatekeeper/gatekeeper  \
    --name-template=gatekeeper \
    --namespace gatekeeper-system --create-namespace \
    --set enableExternalData=true \
    --set controllerManager.dnsPolicy=ClusterFirst,audit.dnsPolicy=ClusterFirst \
    --version 3.10.0
```
_Note: This repository is currently only working with Gatekeeper 3.10 and the `externalData` feature in `alpha`. There is an open issue to track the support of Gatekeeper 3.11 and `externalData` feature in `beta`: https://github.com/scribe-security/gatekeeper-valint/issues/20._

Let's install the `gatekeeper-valint`:

- `kubectl apply -f manifest`

- `kubectl apply -f manifest/provider.yaml`
  > Update `url` if it's not `http://gatekeeper-valint.gatekeeper-valint:8090` (default)

- `kubectl apply -f policy/template.yaml`

- `kubectl apply -f policy/constraint.yaml`

# External Data Provider

A template repository for building external data providers for Gatekeeper.

## Prerequisites

- [ ] [`docker`](https://docs.docker.com/get-docker/)
- [ ] [`helm`](https://helm.sh/)
- [ ] [`kubectl`](https://kubernetes.io/docs/tasks/tools/#kubectl)

## Quick Start
Gatekeeper should deny the pod admission because.

```console
Error from server (Forbidden):
```

6. Uninstall the external data provider and Gatekeeper.

```bash

```
