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

1) To generate new certificates, use the script:
- `scripts/generate-tls-cert.sh`

2) This will create CA and certificate files in `certs` directory.

### Installing Valint Gatekeeper provider

- ```sh
   helm install charts/gatekeeper-valint --name-template=gatekeeper-valint \
   --namespace gatekeeper-valint --create-namespace \
   --set certs.caBundle=$(cat certs/ca.crt | base64 | tr -d '\n') \
   --set certs.tlsCrt="$(cat certs/tls.crt)" \
   --set certs.tlsKey="$(cat certs/tls.key)"
  ```

If Valint verification is to be performed with x509 certificate, provide additional flags.

- ```sh
   helm install charts/gatekeeper-valint --name-template=gatekeeper-valint \
   --namespace gatekeeper-valint --create-namespace \
   --set certs.caBundle=$(cat certs/ca.crt | base64 | tr -d '\n') \
   --set certs.tlsCrt="$(cat certs/tls.crt)" \
   --set certs.tlsKey="$(cat certs/tls.key)" \
   --set x509.cert="$(cat valint/tls.crt)" \
   --set x509.ca="$(cat valint/ca.crt)"
  ```

### Evidence Stores
Each storer can be used to store, find and download evidence, unifying all the supply chain evidence into a system is an important part to be able to query any subset for policy validation.

| Type  | Description | requirement |
| --- | --- | --- |
| scribe | Evidence is stored on scribe service | scribe credentials |
| OCI | Evidence is stored on a remote OCI registry | access to a OCI registry |

## Scribe Evidence store
Scribe evidence store allows you store evidence using scribe Service.

### Before you begin
Integrating Scribe Hub with admission controller requires the following credentials that are found in the **Integrations** page. (In your **[Scribe Hub](https://prod.hub.scribesecurity.com/ "Scribe Hub Link")** go to **integrations**)

* **Client ID**
* **Client Secret**

<img src='../../../img/ci/integrations-secrets.jpg' alt='Scribe Integration Secrets' width='70%' min-width='400px'/>

Enable Scribe client and add related `Client ID` and `Client Secret`.

- ```sh
   helm install charts/gatekeeper-valint --name-template=gatekeeper-valint \
   --namespace gatekeeper-valint --create-namespace \
   --set certs.caBundle=$(cat certs/ca.crt | base64 | tr -d '\n') \
   --set certs.tlsCrt="$(cat certs/tls.crt)" \
   --set certs.tlsKey="$(cat certs/tls.key)" \
   --set scribe.enable=true \
   --set scribe.client_id=$SCRIBE_CLIENT_ID \
   --set scribe.client_secret=$SCRIBE_CLIENT_SECRET
  ```
> Credentials will be stored as a secret named `scribe-cred-secret`.

## OCI Evidence store
Valint supports both storage and verification flows for `attestations` and `statement` objects using an OCI registry as an evidence store. <br />
Using OCI registry as an evidence store allows you to upload and verify evidence across your supply chain in a seamless manner.

Related configmap flags:
>* `config.attest.cocosign.storer.OCI.enable` - Enable OCI store.
>* `config.attest.cocosign.storer.OCI.repo` - Evidence store location.

## Private registries
To verify images from registries that require authentication, create a Kubernetes image pull secret named `gatekeeper-valint-pull-secret`.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: gatekeeper-valint-pull-secret
  namespace: gatekeeper-valint
data:
  .dockerconfigjson: ewoJImF1...g==
type: kubernetes.io/dockerconfigjson
```

### Dockerhub limitation
Dockerhub does not support the subpath format, `oci-repo` should be set to your Dockerhub Username.

> Some registries like Jfrog allow multi layer format for repo names such as , `my_org.jfrog.io/policies/attestations`.

### Before you begin
- Write access to upload evidence using the `valint` tool.
- Read access to download evidence for the provider.
- Evidence can be stored in any accessible OCI registry.

1. Edit the `charts/gatekeeper-valint/values.yaml` file, enable OCI client and enable a OCI repo.
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
     
## Verification

## See Gatekeeper Valint in action
By **default** Valint policy is a simplistic verify signature policy.

```bash
kubectl apply -f policy/examples/error.yaml
```
Request should be rejected.

```
  Error from server (Forbidden): error when creating "policy/examples/error.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [gatekeeper-valint] image not accepted: {"errors": [], "responses": [], "status_code": 200, "system_error": "ERROR (VerifyAdmissionImage(\"scribesecuriy.jfrog.io/scribe-docker-public-local/test/gensbom_alpine_input:latest\")): [rule] [my_policy] [verify-artifact] [verify_rego] verify, Err: [my_policy] [verify-artifact] [verify_rego] rule failed"}
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
See `charts/gatekeeper-valint/values.yaml`, valint.config section and Valint documentation for more details.
