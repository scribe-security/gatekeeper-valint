# Bootstrap demo - Enforce Image signing.
This demonstration showcases the implementation of image signing policies through Gatekeeper Valint. It provides a step-by-step guide for setting up and executing the process, ensuring secure image deployments within your Kubernetes environment. Specifically, this demo emphasizes the utilization of Valint with a client-based CA (X509) while employing OCI as the signature storage.

## Step 1: Install Valint Locally
First, let's install Valint locally for testing purposes. We'll use a pre-release version until we transition to v1.2.1.

```bash
curl -sSfL https://get.scribesecurity.com/install.sh | sh -s -- -t valint -D
```

> Install Valint should append `-D` flag is currently used, By April 1, this flag can be omitted in favor of the release candidate.

## Step 2: Setup Gatekeeper`
Now, we'll set up Gatekeeper in our Kubernetes cluster. This step involves installing the Gatekeeper Helm chart with specific configurations.

```bash
helm install gatekeeper/gatekeeper \
    --name-template=gatekeeper \
    --namespace gatekeeper-system --create-namespace \
    --set enableExternalData=true \
    --set controllerManager.dnsPolicy=ClusterFirst,audit.dnsPolicy=ClusterFirst \
    --set validatingWebhookTimeoutSeconds=30
```

>  Enabling the `enableExternalData` feature is essential for our deployment scenario. We should consider enabling it on the running instance.

## Step 3: Generate TLS and Signing Keys
Execute the help script to create keys.

* TLS keys facilitate communication with the Provider. (`certs/tls.crt`, `certs/tls.key`)
* Signing keys are utilized for the signing and validation of images. It's advised to employ a trusted CA for signing rather than demonstration ones. (`certs/evidence.crt`, `certs/evidence.key`)
* Both key pairs are generated under the same ca (`certs/ca.crt`).

```bash
curl -sSfL https://raw.githubusercontent.com/scribe-security/gatekeeper-valint/main/scripts/generate-tls-cert.sh  | bash
```

## Step 4: Setup Valint Gatekeeper Provider
In this step, we'll configure the Valint Gatekeeper Provider. This involves setting up CA-based verification with a demo Root CA and OCI-based signatures against a dedicated OCI registry repository. We'll also disable the default behavior of pushing evaluation reports to OCI to minimize permissions.

```bash
helm repo add scribe https://scribe-security.github.io/gatekeeper-valint
helm repo update
helm search repo scribe --devel
helm install scribe/gatekeeper-valint --name-template=gatekeeper-valint \
    --namespace gatekeeper-valint --create-namespace \
    --set certs.caBundle=$(cat certs/ca.crt | base64 | tr -d '\n') \
    --set certs.tlsCrt="$(cat certs/tls.crt)" \
    --set certs.tlsKey="$(cat certs/tls.key)" \
    --set constraint.namespace=demo-valint \
    --set valint.attest.report.disable=true \
    --set valint.attest.default=x509-env \
    --set x509.ca="$(cat certs/ca.crt)" \
    --set image.imagePullSecrets="$(cat ~/.docker/config.json | base64 | tr -d '\n')" \
    --set valint.attest.cocosign.storer.OCI.repo="scribesecuriy.jfrog.io/scribe-docker-local/attestation/" \
    --set valint.attest.cocosign.storer.OCI.enable=true \
    --devel
```

> The `--devel` flag is currently used for the Helm provider. By April 1, this flag can be omitted in favor of the release candidate.


## Step 5: Configure Policy
Next, let's configure Gatekeeper constraints, scoped by namespace. This step involves installing policies for signature checks.

```bash
helm upgrade gatekeeper-valint scribe/gatekeeper-valint \
    --values signed_image_policy.yaml \
    --namespace gatekeeper-valint \
    --reuse-values --force \
    --devel
```

> The `--devel` flag is currently used for the Helm provider. By April 1, this flag can be omitted in favor of the release candidate.


<details>
  <summary> signed_image_policy.yaml file </summary>

```yaml
select:
  gate: signed_images_gate
  apply:
  - namespace: "" # Any
    glob:
    - "scribesecurity/**"
    filter-by:
    - target
    policy:
      name: require_signed_images
      rules:
      - name: error_on_unsigned_image
        uses: sboms/artifact-signed@v1
        level: error
        # evidence: Enforce CI origin
        #     context-type: jenkins
```

In the provided `signed_image_policy.yaml`, we specify a policy to enforce signature verification for images admitted from the my_company Dockerhub account.
</details>

## Step 6: Create Demo Namespace
We'll create a demo namespace in our Kubernetes cluster where we'll deploy our demo application.

```bash
kubectl create namespace demo-valint
```

## Step 7: Create Evidence Locally
To resolve the unsigned image error, we'll create evidence locally using the Valint tool. This evidence will be used to validate the image signatures.

```bash
valint bom scribesecurity/signed:latest -o attest \
    --components metadata \
    --attest.default=x509 \
    --key certs/evidence.key \
    --cert certs/evidence.crt \
    --ca certs/ca.crt \
    --oci --oci-repo "scribesecuriy.jfrog.io/scribe-docker-local/attestation"
```

This concludes our demo script for enforcing image signing policies with Gatekeeper Valint.

<details>
  <summary>  Create Evidence On jenkins </summary>

Alternatively, we can implement a pipeline to sign our images directly on the CI system itself. This approach enables the collection of CI-based information such as pipeline and build run ID.

```javascript
pipeline {
  agent any
  environment {
    PATH="./temp/bin:$PATH"
  }
  stages {
    BUILD IMAGE STAGES.
    ...
    stage('Install Valint') {
        steps {
          sh 'curl -sSfL https://get.scribesecurity.com/install.sh | sh -s -- -b ./temp/bin' -D
        }
    }
    stage('Sign Image') {
      steps {        
        withCredentials([file(credentialsId: 'attest-key', variable: 'ATTEST_KEY_PATH'),
            file(credentialsId: 'attest-cert', variable: 'ATTEST_CERT_PATH'),
            file(credentialsId: 'attest-ca', variable: 'ATTEST_CA_PATH')
            {
                    sh '''
                    valint bom scribesecurity/signed:latest -o attest \
                        --context-type jenkins \
                        --output-directory ./scribe/valint \
                        --components metadata \
                        --attest.default x509 \
                        --key $ATTEST_KEY_PATH \
                        --cert $ATTEST_CERT_PATH \
                        --ca $ATTEST_CA_PATH \
                        --oci --oci-repo "scribesecuriy.jfrog.io/scribe-docker-local/attestation
                    '''
            }
      }
    }
```

* The pipeline requires write permissions to the oci-repo.
* The pipeline needs read permission for scribesecurity/signed:latest.

> Set the context-type to jenkins, allowing you to enforce images to be signed by a specific pipeline.

> Install Valint should append `-D` flag is currently used, By April 1, this flag can be omitted in favor of the release candidate.

</details>

## Step 8: Admit Demo Deployments
Now, let's admit a deployment into our demo namespace. We'll deploy a sample application, which will be rejected due to unsigned images.

```bash
kubectl apply -f signed-deployment.yaml -n demo-valint 2>&1 | echo -e "$(cat -)"
```

## Step 9: Reviewing Results
You can review results by looking at logs.
```bash
kubectl logs -n gatekeeper-valint $(kubectl get pods -n gatekeeper-valint | grep gatekeeper-valint | head -1 | awk '{print $1}') | sed -r "s/\x1B\[[0-9;]*[mK]//g; s/\r//g"
```
