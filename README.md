# Valint Gatekeeper Provider
To integrate [OPA Gatekeeper's new ExternalData feature](https://open-policy-agent.github.io/gatekeeper/website/docs/externaldata) with Valint to verify policies on your supply chain.

> This repo is meant for testing Gatekeeper external data feature. Do not use for production.

## Installation

### Installing Gatekeeper
- Deploy Gatekeeper with external data enabled (`--enable-external-data`)
```sh
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm install gatekeeper/gatekeeper  \
    --name-template=gatekeeper \
    --namespace gatekeeper-system --create-namespace \
    --set enableExternalData=true \
    --set controllerManager.dnsPolicy=ClusterFirst,audit.dnsPolicy=ClusterFirst \
    --set validatingWebhookTimeoutSeconds=30 \
```

### Generate TLS certificate and key for the provider
Gatekeeper enforces TLS when communicating with the provider, so certificates must be provided.

To generate new certificates, use the script:
- `scripts/generate-tls-cert.sh`

This will create CA and certificate files in `certs` directory.
Copy the contents of `tls.crt` and `tls.key` to the corresponding field in `manifest/certs.yaml`.

Base64 encode the CA certificate and update the `caBundle` field in `policy/provider.yaml` with the resulting value.

`cat ca.crt | base64 | tr -d '\n'`

### Installing Valint Gatekeeper provider

- `kubectl apply -f manifest`

- `kubectl apply -f policy/provider.yaml`
  - > Update `url` if it's not `https://gatekeeper-valint.gatekeeper-valint:8090` (default)

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
Request should be rejected.

```
  Error from server (Forbidden): error when creating "policy/examples/valid.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [gatekeeper-valint] image not accepted: {"errors": [], "responses": [], "status_code": 200, "system_error": "ERROR (VerifyAdmissionImage(\"scribesecuriy.jfrog.io/scribe-docker-public-local/test/gensbom_alpine_input:latest\")): [rule] [my_policy] [verify-artifact] [verify_rego] verify, Err: [my_policy] [verify-artifact] [verify_rego] rule failed"}
  Error from server (Forbidden): error when creating "policy/examples/error.yaml": admission webhook "validation.gatekeeper.sh" denied the request
```

This will successfully create the pod demo using a demo signed image.
```bash
kubectl apply -f policy/examples/valid.yaml
```

Request should result in a successful deploy.

```
  deployment.apps/valid-deployment created
```

## Uploading signed evidence
Using valint `-o attest` flag you can upload signed evidence on the image.
```bash
valint [bom, slsa] my_image -o attest [--oci OR --scribe.enable]
```

## Adding custom policies
The configuration of the Valint provider is done via a ConfigMap.
The same parameters and flags as in Valint can be set.
See manigest/configmap.yaml and Valint documentation for more details.
