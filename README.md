# Valint Gatekeeper Provider
To integrate [OPA Gatekeeper's new ExternalData feature](https://open-policy-agent.github.io/gatekeeper/website/docs/externaldata) with Valint to verify policies on your supply chain.

> This repo is meant for testing Gatekeeper external data feature. Do not use for production.

## Installation

### Installing gatekeeper
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

### Installing Valint Gatekeeper provider
- `kubectl apply -f manifest`

- `kubectl apply -f policy/provider.yaml`
  - > Update `url` if it's not `http://gatekeeper-valint.gatekeeper-valint:8090` (default)

- `kubectl apply -f policy/template.yaml`

- `kubectl apply -f policy/constraint.yaml`

### Evidence Stores
Each storer can be used to store, find and download evidence, unifying all the supply chain evidence into a system is an important part to be able to query any subset for policy validation.

| Type  | Description | requirement |
| --- | --- | --- |
| scribe | Evidence is stored on scribe service | scribe credentials |
| OCI | Evidence is stored on a remote OCI registry | access to a OCI registry |

## Scribe Evidence store
Scribe evidence store allows you store evidence using scribe Service.

Related Deployment environments:
> Note the values set:
>* `VALINT_SCRIBE_AUTH_CLIENT_ID`
>* `VALINT_SCRIBE_AUTH_CLIENT_SECERT`
>* `VALINT_SCRIBE_ENABLE`

### Before you begin
Integrating Scribe Hub with admission controller requires the following credentials that are found in the **Integrations** page. (In your **[Scribe Hub](https://prod.hub.scribesecurity.com/ "Scribe Hub Link")** go to **integrations**)

* **Client ID**
* **Client Secret**

<img src='../../../img/ci/integrations-secrets.jpg' alt='Scribe Integration Secrets' width='70%' min-width='400px'/>

1. Edit the `manifest/secret.yaml` file, enable client and add  related `Client ID` and `Client Secret`.

  For example.
  ```yaml
  apiVersion: v1
  kind: Secret
  metadata:
    name: scribe-cred-secret
    namespace: gatekeeper-valint
  stringData:
    scribe_client_id: "<your client secret>"
    scribe_client_secret: "<your client secret>"
    scribe_enable: "true"
  ```

2. To install the gatekeeper-valint with Scribe service integration:
```bash
    kubectl apply -f manifest
    # Update `url` if it's not `http://gatekeeper-valint.gatekeeper-valint:8090` (default)
    kubectl apply -f policy/provider.yaml

    kubectl apply -f policy/template.yaml
    kubectl apply -f policy/constraint.yaml
```

> Credentials will be stored as a secret named `scribe-cred-secret`.

## OCI Evidence store
Valint supports both storage and verification flows for `attestations` and `statement` objects using an OCI registry as an evidence store. <br />
Using OCI registry as an evidence store allows you to upload and verify evidence across your supply chain in a seamless manner.

Related configmap flags:
>* `config.attest.cocosign.storer.OCI.enable` - Enable OCI store.
>* `config.attest.cocosign.storer.OCI.repo` - Evidence store location.
<!-- * `imagePullSecrets` - Secret name for private registry. -->

### Dockerhub limitation
Dockerhub does not support the subpath format, `oci-repo` should be set to your Dockerhub Username.

> Some registries like Jfrog allow multi layer format for repo names such as , `my_org.jfrog.io/policies/attestations`.

### Before you begin
- Write access to upload evidence using the `valint` tool.
- Read access to download evidence for the provider.
- Evidence can be stored in any accessible OCI registry.

1. Edit the `manifest/configmap.yaml` file, enable OCI client and enable a OCI repo.
   For example, 
   ```yaml
   attest:
    cocosign:
      storer:
        OCI:
          enable: true
          repo: <optional oci-repo>
   ```

   > [oci-repo] is the URL of the OCI repository where all evidence will be uploaded.
      - Example: If your oci repo is `somewhere/evidence_store` create a evidence for `example/my_image:latest`, the evidence will be stored as under `somewhere/evidence_store/image/SHA-256-DIGEST.sig`

   > Empty `oci-repo` will Attach the evidence to the same repo as the uploaded image.
    - Example: If you create a evidence for `example/my_image:latest`, the evidence will be stored as `example/my_image:SHA-256-DIGEST.sig` (oci-repo).

<!-- 2. If [oci-repo] is a private registry, attach permissions to the admission with the following steps:
    1. Create a secret:
    ```bash
    kubectl create secret docker-registry [secret-name] --docker-server=[registry_url] --docker-username=[username] --docker-password=[access_token] -n gatekeeper-valint
    ``` -->
     
2. To install the gatekeeper-valint with Scribe service integration:
```bash
    kubectl apply -f manifest
    # Update `url` if it's not `http://gatekeeper-valint.gatekeeper-valint:8090` (default)
    kubectl apply -f policy/provider.yaml

    kubectl apply -f policy/template.yaml
    kubectl apply -f policy/constraint.yaml
```

## Verification

## See Gatekeeper Valint in action
By **default** Valint policy is a simplistic verify signature policy.

```bash
kubectl apply -f policy/examples/error.yaml
```
Request should be rejected as the image was not signed.

```
  TBD output expected
```

This will successfully create the pod demo using a demo signed image.
```bash
kubectl apply -f policy/examples/valid.yaml
```
Request should be successfully deploy.

```
  TBD output expected
```

## Uploading signed evidence
Using valint `-o attest` flag you can upload signed evidence on the image.
```bash
valint [bom, slsa] my_image -o attest [--oci OR --scribe.enable]
```

## Adding custom policies
TBD
















# gatekeeper-valint
To integrate [OPA Gatekeeper's new ExternalData feature](https://open-policy-agent.github.io/gatekeeper/website/docs/externaldata) with [cosign](https://github.com/sigstore/cosign) to determine whether the images are valid by verifying its signatures.

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

## Verification

To test this successfully, we should sign one of our images with [cosign](https://github.com/sigstore/cosign#installation) tool. So, let's do this first:

Generate key pair
```shell
$ cosign generate-key-pair
```

We have two files under `policy/examples`, one for valid manifest that contains signed image, the other is invalid. To do the same you should sign your image as I did:

```shell
$ crane copy alpine:latest devopps/alpine:signed
$ crane copy alpine:3.14 devopps/alpine:unsigned
$ cosign sign --key cosign.key devopps/signed:latest
```

So, once you are ready, let's apply these manifests one by one. It should allow deploying Pod for valid.yaml, and deny for the other one.
# External Data Provider

A template repository for building external data providers for Gatekeeper.

## Prerequisites

- [ ] [`docker`](https://docs.docker.com/get-docker/)
- [ ] [`helm`](https://helm.sh/)
- [ ] [`kind`](https://kind.sigs.k8s.io/)
- [ ] [`kubectl`](https://kubernetes.io/docs/tasks/tools/#kubectl)

## Quick Start

1. Create a [kind cluster](https://kind.sigs.k8s.io/docs/user/quick-start/).

2. Install the latest version of Gatekeeper and enable the external data feature.

```bash
# Add the Gatekeeper Helm repository
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts

# Install the latest version of Gatekeeper with the external data feature enabled.
helm install gatekeeper/gatekeeper \
    --set enableExternalData=true \
    --name-template=gatekeeper \
    --namespace gatekeeper-system \
    --create-namespace
```

3. Build and deploy the external data provider.

```bash
git clone https://github.com/open-policy-agent/gatekeeper-external-data-provider.git
cd external-data-provider

# if you are not planning to establish mTLS between the provider and Gatekeeper,
# deploy the provider to a separate namespace. Otherwise, do not run the following command
# and deploy the provider to the same namespace as Gatekeeper.
export NAMESPACE=provider-system

# generate a self-signed certificate for the external data provider
./scripts/generate-tls-cert.sh

# build the image via docker buildx
make docker-buildx

# load the image into kind
make kind-load-image

# Choose one of the following ways to deploy the external data provider:

# 1. client and server auth enabled (recommended)
helm install external-data-provider charts/external-data-provider \
    --set provider.tls.caBundle="$(cat certs/ca.crt | base64 | tr -d '\n\r')" \
    --namespace "${NAMESPACE:-gatekeeper-system}" --create-namespace

# 2. client auth disabled and server auth enabled
helm install external-data-provider charts/external-data-provider \
    --set clientCAFile="" \
    --set provider.tls.caBundle="$(cat certs/ca.crt | base64 | tr -d '\n\r')" \
    --namespace "${NAMESPACE:-gatekeeper-system}" \
    --create-namespace
```

4a. Install constraint template and constraint.

```bash
kubectl apply -f validation/external-data-provider-constraint-template.yaml
kubectl apply -f validation/external-data-provider-constraint.yaml
```

4b. Test the external data provider by dry-running the following command:

```bash
kubectl run nginx --image=error_nginx --dry-run=server -ojson
```

Gatekeeper should deny the pod admission above because the image field has an `error_nginx` prefix.

```console
Error from server (Forbidden): admission webhook "validation.gatekeeper.sh" denied the request: [deny-images-with-invalid-suffix] invalid response: {"errors": [["error_nginx", "error_nginx_invalid"]], "responses": [], "status_code": 200, "system_error": ""}
```

5a. Install Assign mutation.

```bash
kubectl apply -f mutation/external-data-provider-mutation.yaml
```

5b. Test the external data provider by dry-running the following command:

```bash
kubectl run nginx --image=nginx --dry-run=server -ojson
```

The expected JSON output should have the following image field with `_valid` appended by the external data provider:

```json
"containers": [
    {
        "name": "nginx",
        "image": "nginx_valid",
        ...
    }
]
```

6. Uninstall the external data provider and Gatekeeper.

```bash
kubectl delete -f validation/
kubectl delete -f mutation/
helm uninstall external-data-provider --namespace "${NAMESPACE:-gatekeeper-system}"
helm uninstall gatekeeper --namespace gatekeeper-system
```
