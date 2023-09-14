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
Copy the contents of `certs/tls.crt` and `certs/tls.key` to the corresponding fields in `manifest/certs.yaml`.

For example,
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: valint-certs
  namespace: gatekeeper-valint
type: kubernetes.io/tls
stringData:
  tls.crt: |
    -----BEGIN CERTIFICATE-----
    MIIDYDCCAkigAwIBAgIUEpXWyJEaoi5LtKKEtOG2Vd2WB9IwDQYJKoZIhvcNAQEL
    BQAwMjETMBEGA1UECgwKR2F0ZWtlZXBlcjEbMBkGA1UEAwwSR2F0ZWtlZXBlciBS
    b290IENBMB4XDTIzMDkxMzEzMTAwNFoXDTIzMDkxNDEzMTAwNFowLjEsMCoGA1UE
    AwwjZ2F0ZWtlZXBlci12YWxpbnQuZ2F0ZWtlZXBlci12YWxpbnQwggEiMA0GCSqG
    SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCr7XfyeDGUqIMHraDVO7kuzQwVuBQ5M9Nr
    LHEY+6N7+mcDvcjjhrjNv/OQi43Vfi1zt2OfT0Je6zCWcY1kD7zKndYEfPmDNfqm
    2YNPXT14tVnSnvc+7ffkUEgnS7CLjUIsOc11RcJRRvaj9W9rfB+AYz0tG31gWniU
    YRg4LlKUJW3V/mGMA7+4z7XROwbNDdjEPeBBXa9H7EOXUcfwCCCuC3QL2fcW/0CJ
    0iz3nme1Vm4jZZexAvlJlBbQ0yLBUoj8pCbq8l0edxZhpwHKNSGn039VkZTme/Rc
    eU9oomMEqMRysew18iVu93uusJYiG4o6p0HqDEGsoI0SJAj58+X3AgMBAAGjcjBw
    MC4GA1UdEQQnMCWCI2dhdGVrZWVwZXItdmFsaW50LmdhdGVrZWVwZXItdmFsaW50
    MB0GA1UdDgQWBBTfnVPXFs2l2zvCPAsIepycPOR5hzAfBgNVHSMEGDAWgBTsvEkL
    YDtM6QRBHQ4a5fZvilKYwDANBgkqhkiG9w0BAQsFAAOCAQEAdvS254F4nwfzLmKR
    DHDbEVz19IgQsI/U35M114QBe3IFM2FpzLZ+7jvIxnm+Hsv7t4KxF6YsIzaoaMew
    /XoIaEvytdDIJlOS9bqwBqC0ehINT5OHzje77LgZa5Ns/ymTvmU30lBMQ/QV2E5+
    x6I0fp3TNnnXNBr8Ni751KuSi93h86+Yvwsk7+vIaIfBYVAbNRmUkSxT9tDhrXxW
    iSWT4DENp6e1SY4ST6FqwlODJhMTeJsVedJQTbLtKroqUsJB8VqCCWXZS9iYPVyr
    LmCeoMRLYYMagw9jw4koHyPy18FDwTWPIuHUqNhFFlAflBIjhxtjhzA7TmjtGeqQ
    bmHrFw==
    -----END CERTIFICATE-----
  tls.key: |
    -----BEGIN PRIVATE KEY-----
    MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCr7XfyeDGUqIMH
    raDVO7kuzQwVuBQ5M9NrLHEY+6N7+mcDvcjjhrjNv/OQi43Vfi1zt2OfT0Je6zCW
    cY1kD7zKndYEfPmDNfqm2YNPXT14tVnSnvc+7ffkUEgnS7CLjUIsOc11RcJRRvaj
    9W9rfB+AYz0tG31gWniUYRg4LlKUJW3V/mGMA7+4z7XROwbNDdjEPeBBXa9H7EOX
    UcfwCCCuC3QL2fcW/0CJ0iz3nme1Vm4jZZexAvlJlBbQ0yLBUoj8pCbq8l0edxZh
    pwHKNSGn039VkZTme/RceU9oomMEqMRysew18iVu93uusJYiG4o6p0HqDEGsoI0S
    JAj58+X3AgMBAAECggEAVV2dE4cLczkyijLzazzyx2Knb/dND1QE0y+nXlS/yXS9
    BpYKs7J2ey6mhKxOOeWjMtQpgnYLye50Wxa5sifAQUiadfMJvtUkBgl1UghFV/SP
    y20D7bqhvbsBAIXr/Hagly4CLor7H3khSKq6bn+ccpaTzxxZpeh1+5K0QFz7wrN8
    LM7QHAQ89DLKTGZ5ptRIEKVILKUQIlAYAopTWIMMhPz2U7IsQctuLE3qn5IjZtTE
    9Ovst4PV0sdawfBovQNgffaJczt1rSYI2iow7j1ocbyt2i+iXJCEvbLUyroZRgZj
    NmC0GbEswh6QhgWYuBT8JhP0Y0zT8QXr1nQ2mMF2VQKBgQDEj5cbE/Yamz70GyfY
    wvIaoM+ykG0ZGfvj0/7WzxyBM2j9ROQ+kOOktoyA2WWFLo6hMQz447IaI2/fflPu
    599xIhRye1zHwveZ5127KfQnq4iSZTe3gA+Mp5kJhBI7ouytu+qpnzjYbNG/+5U9
    QHqYy3fGYHHGCkAolm3f0RI4awKBgQDf6u+7KczeCt8K27OB5IkYtY0xLEZSAAJI
    84Lqn68i6SjxKSlCN+c8zuzEPyHapdaox68IG5noSCVMK/djGpekzmcJU+2b/hME
    sPxo0Sk5ZrbTiXkKt5HerueDyHJmf6r3z1IMTnRNeWMEVgivOr3reXeMsZYdYypR
    p37gzVbbpQKBgE2XGODZelZ6XdliNtJ78bHNNO+Zz1cPSL1gW8JTsz7VGmaPoUGJ
    VDMa1E+wgUCXZjn+8M32o8Fpp6mjZmJyKWOxPj0KsU8xiSe5iuhs4TIfpiOTzPCk
    nn65UdHNzpy37ZGPEkyuy3OzUQDlwL2TDFHwT3GBdKfmN/lNmEW3c+fNAoGBAIxF
    Yb6O1f73Mnhb31zsrJGlEfkO8lJmHQhUO9v9ArrM80/36BfKa3plal8Z6XxOTWXY
    Cab7m3Ou1macWFJmEz8z6conIH+LL6DNuqFy/e8ukDN+OCxliOTGDtQ4WqopKhIp
    dw2sjCEIfOX3e2NCWj1MD388tHxeZeFXGx16pQHdAoGBAKaI0fzwD4x3vQtYw8O6
    HAFHcWD22z+5Y/4vkVsoYcIBObE9PDV/Y8QSxsVah7LaAxgzcO+XY0+0Y5D1kcmo
    yTNMDLm2ISOPI4UGQU1rLQmgRTEFsrIHKVHwHIXD7o0S2JQY55sH5imO3+SIns4E
    bNSMdv/eZqBF9S4qWzM4PEvS
    -----END PRIVATE KEY-----
```

3) Base64 encode the CA certificate and update the `caBundle` field in `policy/provider.yaml` with the resulting value.

```bash
cat certs/ca.crt | base64 | tr -d '\n'
```

For example,

``` yaml
apiVersion: externaldata.gatekeeper.sh/v1beta1
kind: Provider
metadata:
  name: gatekeeper-valint
spec:
  url: https://gatekeeper-valint.gatekeeper-valint:8090/validate
  timeout: 30
  caBundle: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURSVENDQWkyZ0F3SUJBZ0lVSlhzNWJNVCtPTm1pRFE3cFdxUFdYNjBUSmY0d0RRWUpLb1pJaHZjTkFRRUwKQlFBd01qRVRNQkVHQTFVRUNnd0tSMkYwWld0bFpYQmxjakViTUJrR0ExVUVBd3dTUjJGMFpXdGxaWEJsY2lCUwpiMjkwSUVOQk1CNFhEVEl6TURreE16RXpNVEF3TkZvWERUSXpNRGt4TkRFek1UQXdORm93TWpFVE1CRUdBMVVFCkNnd0tSMkYwWld0bFpYQmxjakViTUJrR0ExVUVBd3dTUjJGMFpXdGxaWEJsY2lCU2IyOTBJRU5CTUlJQklqQU4KQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBamdhZTgzSUF4d0RBeFJiamZxdWlYOVVqVzFEMApBT1hYRmNvamtBWVI2RWNmSWNCWWZBa0YxRWFubjFubjBCVU5adkhucEFkeHhHZnpQODVDSEluTzVHcmgxS0NNClovQU0yRVUyZi9oQzRWcXFvYUJSRWxWV1BQTmJxMGJLZ1Faa3BBeUw2TkdWTUNaQUxuYnk4ZlpKOUZwWmJMbXkKaFBhK3FVbVU3aEdsTno4V1JKdVU3VnlMdnVEa2FQa0NFUExBYmJ1dTVsc3ZlVXZMMWZENloyVDlOYnFib1pkTwpOYTlDRkp3azBVSEpLcGdMTUkxQWwxRkZzbW03eHpVV0l4Z0FxWjhJSzkwSFIrQlNndDJBdmVTUVpDL1pKMnlpCjV3SHA3dUxtZ0NDSWVHeXRaeUhEQTVBZ3NvYmJ4S3RFdHVURVZkd2hkVStpVzFDNXJTTTFIY1dJaHdJREFRQUIKbzFNd1VUQWRCZ05WSFE0RUZnUVU3THhKQzJBN1RPa0VRUjBPR3VYMmI0cFNtTUF3SHdZRFZSMGpCQmd3Rm9BVQo3THhKQzJBN1RPa0VRUjBPR3VYMmI0cFNtTUF3RHdZRFZSMFRBUUgvQkFVd0F3RUIvekFOQmdrcWhraUc5dzBCCkFRc0ZBQU9DQVFFQVRsUWZsRExpKzNwT1h0aUd4Y2J6TGp3b3ZreTBOLzJFQWJvUG5DalIvdWRqY1NYcWFkbjYKQkZOT0paVzV6akU2MUI2cVFYcGtPQnBnRVB6N0hOTWdLZFRoTjdQc25zeitVNExvdWxPU3MvU3BKaWN1V1VnTwpJUlkrUUVrU2ZydVZxWGc1Tkl2QTJzVXZOUkpscU00UlZrSzdGN29CODRWRXM5NDQrUWxMaVp5cGFsUmVBQWY2ClJ4dXJTM1FOQlYwNkVlV2pWOUViMXBMbVpleS8vTW04ajRkR21ScitYZjVxYmwvelZmRmhCdjR4Y1BXRkY5T0UKM1YvRjVreDJvWW1jRzJvZFJ1VWZ6OUJXQ0VSQm01Mlp0L2xwL2JuNDdrTDdIVEduOW5sSEhLUXpsMVJLbGRqNApSTStLa213bmtjMGV0aVplZWVSbW8xNzB1M3AwWHJmeUZ3PT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
```

### Installing Valint Gatekeeper provider

- `kubectl apply -f manifest`

Or

- ```sh
   helm install charts/gatekeeper-valint --name-template=gatekeeper-valint \
   --namespace gatekeeper-valint --create-namespace \
   --set certs.caBundle=$(cat certs/ca.crt | base64 | tr -d '\n')
   --set certs.tlsCrt=$(cat certs/tls.crt | base64 | tr -d '\n')
   --set certs.tlsKey=$(cat certs/tls.key | base64 | tr -d '\n')
  ```

In case of using 

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
See manigest/configmap.yaml and Valint documentation for more details.
