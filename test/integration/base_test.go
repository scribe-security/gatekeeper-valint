package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	baseCache "github.com/scribe-security/basecli/cache"
	"github.com/scribe-security/basecli/client/api"
	cocosign_config "github.com/scribe-security/cocosign/signing/config"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/release"
	// "helm.sh/helm/v3/pkg/release"
)

var (
	gatekeeperNamespace = "gatekeeper-system"
	providerNamespace   = "gatekeeper-valint"
	ConfigPath          = "testdata/test.yaml"
	CaPath              = "testdata/keys/ca-chain.cert.pem"
	ConfigPathEnv       = "testdata/test_env.yaml"
	runNum              = os.Getenv("GITHUB_RUN_NUMBER")
	devTag              = "dev-latest"
	releaseTag          = "latest"
)

type runImageAdmissionTestStruct struct {
	name                string
	image               string
	expectedError       string
	bomFlags            []string
	format              string
	store               string
	valuesConfig        map[string]interface{}
	policyConfig        map[string]interface{}
	bomAssertions       []traitAssertion
	admissionAssertions []traitAssertion
}

type StoreTest interface {
	MakeValuesConfig(t *testing.T, sigstore string, caPath string, devTag string) map[string]interface{}
	BomFlags(t *testing.T, command, baseConfig string) []string
	Type() string
}

// ScribeStore represents the implementation for the "scribe" store
type ScribeStoreTest struct{}

func (s *ScribeStoreTest) BomFlags(t *testing.T, command, baseConfig string) []string {
	scribeURL, found := os.LookupEnv("SCRIBE_URL")
	require.True(t, found, "Scribe url not found")

	scribeClientID, found := os.LookupEnv("SCRIBE_CLIENT_ID")
	require.True(t, found, "Scribe client id not found")

	scribeClientSecret, found := os.LookupEnv("SCRIBE_CLIENT_SECRET")
	require.True(t, found, "Scribe client secret not found")

	config := api.Config{
		Auth: api.Auth{
			ClientID:     scribeClientID,
			ClientSecret: scribeClientSecret,
			Enable:       true,
		},
		ServiceCfg: api.ServiceCfg{
			URL:    scribeURL,
			Enable: true,
		},
	}

	return BaseFlags(command, &baseCache.Config{Enable: false}, &config, &cocosign_config.OCIStorer{}, baseConfig)
}

func (s *ScribeStoreTest) MakeValuesConfig(t *testing.T, sigstore string, caPath string, tag string) map[string]interface{} {
	return PrepareScribeConfigE2E(t, sigstore, caPath, tag)
}

func (s *ScribeStoreTest) Type() string {
	return "scribe"
}

// OCIStore represents the implementation for the "OCI" store
type OCIStoreTest struct{}

// Implement methods required by the Store interface for the "OCI" store
func (s *OCIStoreTest) BomFlags(t *testing.T, command, baseConfig string) []string {
	repo, found := os.LookupEnv("SCRIBE_OCI_REPO")
	require.True(t, found, "OCI REPO not found")

	ociConfig := cocosign_config.OCIStorer{
		Enable: true,
		Repo:   repo,
	}

	return BaseFlags(command, &baseCache.Config{}, &api.Config{}, &ociConfig, baseConfig)
}

func (o *OCIStoreTest) MakeValuesConfig(t *testing.T, sigstore string, caPath string, tag string) map[string]interface{} {
	// Implementation for "OCI" store
	return PrepareOCIConfigE2E(t, sigstore, caPath, tag)
}

func (s *OCIStoreTest) Type() string {
	return "OCI"
}

func runImageAdmissionTest(t *testing.T, test runImageAdmissionTestStruct, clientset *kubernetes.Clientset, bomFlags []string) {

	if bomFlags != nil {
		t.Log("###### Running ", bomFlags, "######")
		_, out, err := runCmd(t, bomFlags...)

		debug, found := os.LookupEnv("DEBUG")
		if found && strings.ToLower(debug) == "true" {
			t.Logf(out)
		}
		require.NoError(t, err)
	}

	WaitForProviderPod(t, clientset)

	err := ApplyK8sManifest(t, clientset, test.image)

	logs := GetProviderLogs(t, clientset)

	debug, found := os.LookupEnv("DEBUG")
	if found && strings.ToLower(debug) == "true" {
		t.Logf("%v", logs)
	}

	if test.expectedError == "" {
		require.NoError(t, err, "apply test")
	} else {
		t.Log("Apply K8S Error: ", err)
		if err != nil {
			require.Contains(t, err.Error(), test.expectedError)
		}
	}

}

func HelmUninstall(t *testing.T, namespace string, releaseName string, allowFail bool) {
	settings := cli.New()

	actionConfig := new(action.Configuration)
	err := actionConfig.Init(settings.RESTClientGetter(), namespace, os.Getenv("HELM_DRIVER"), t.Logf)
	if !allowFail {
		require.NoError(t, err, "helm init")
	}

	client := action.NewUninstall(actionConfig)
	_, err = client.Run(releaseName)
	if !allowFail {
		require.NoError(t, err, "helm uninstall")
	}
}

func HelmInstall(t *testing.T, namespace string, repo string, chart string, releaseName string, vals map[string]interface{}) (*release.Release, error) {
	settings := cli.New()

	actionConfig := new(action.Configuration)
	err := actionConfig.Init(settings.RESTClientGetter(), namespace, os.Getenv("HELM_DRIVER"), t.Logf)
	require.NoError(t, err)

	client := action.NewInstall(actionConfig)
	client.CreateNamespace = true
	client.ReleaseName = releaseName
	client.NameTemplate = releaseName
	client.Namespace = namespace
	client.Wait = true
	client.Timeout = 300 * time.Second
	var chartPath string

	if strings.HasPrefix(repo, "http") {
		client.RepoURL = repo
		chartPath, err = client.LocateChart(chart, settings)
		require.NoError(t, err)
	} else {
		chartPath = repo
	}

	helmChart, err := loader.Load(chartPath)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	return client.Run(helmChart, vals)
}

func InstallGatekeeper(t *testing.T) {
	_, err := HelmInstall(t, gatekeeperNamespace, "https://open-policy-agent.github.io/gatekeeper/charts",
		"gatekeeper", "gatekeeper", MakeGatekeeperValues())
	if err != nil {
		// UNINSTALL AND TRY AGAIN
		t.Logf("Uninstalling and retrying Error: %s", err)
		UninstallProvider(t, false)
		time.Sleep(10 * time.Second)
		_, err := HelmInstall(t, gatekeeperNamespace, "https://open-policy-agent.github.io/gatekeeper/charts",
			"gatekeeper", "gatekeeper", MakeGatekeeperValues())
		require.NoError(t, err)
	}

}

func UninstallGatekeeper(t *testing.T, allowFail bool) {
	HelmUninstall(t, gatekeeperNamespace, "gatekeeper", allowFail)

}

func InstallProvider(t *testing.T, valuesConfig, policyConfig map[string]interface{}, format string) {
	_, err := HelmInstall(t, providerNamespace, "../../charts/gatekeeper-valint",
		"gatekeeper-valint", "gatekeeper-valint", MakeProviderValues(t, valuesConfig, policyConfig, format))
	if err != nil {
		// UNINSTALL AND TRY AGAIN
		t.Logf("Uninstalling and retrying Error: %s", err)
		UninstallProvider(t, false)
		_, err := HelmInstall(t, providerNamespace, "../../charts/gatekeeper-valint",
			"gatekeeper-valint", "gatekeeper-valint", MakeProviderValues(t, valuesConfig, policyConfig, format))
		require.NoError(t, err)
	}

}

func UninstallProvider(t *testing.T, allowFail bool) {
	HelmUninstall(t, providerNamespace, "gatekeeper-valint", allowFail)
}

func GenerateCertificates(t *testing.T) {
	cmd := []string{"./generate-tls-cert.sh"}
	_, _, err := RunCmd(t, cmd)
	require.NoError(t, err)
}

func k8sClient(t *testing.T) *kubernetes.Clientset {
	GenerateCertificates(t)

	clientset := ConfigureK8s(t)

	return clientset
}

func LoadCertificates(t *testing.T, res map[string]interface{}) {
	ca, err := os.ReadFile("../../certs/ca.crt")
	require.NoError(t, err)

	crt, err := os.ReadFile("../../certs/tls.crt")
	require.NoError(t, err)

	key, err := os.ReadFile("../../certs/tls.key")
	require.NoError(t, err)

	res["certs"] = map[string]interface{}{
		"caBundle": base64.StdEncoding.EncodeToString(ca),
		"tlsCrt":   string(crt),
		"tlsKey":   string(key),
	}
}

func LoadFormat(t *testing.T, format string, scribeConfig map[string]interface{}) {
	res := scribeConfig

	if valintF, ok := res["valint"]; ok {
		if configF, ok := valintF.(map[string]interface{})["config"]; ok {
			if _, ok := valintF.(map[string]interface{})["verify"]; ok {
			} else {
				configM := configF.(map[string]interface{})
				configM["verify"] = map[string]interface{}{
					"input-format": format,
					"format":       format,
				}

				res["valint"] = map[string]interface{}{
					"conifg": configM,
				}
			}
		}
	}
}

func MakeProviderValues(t *testing.T, scribeConfig, policyConfig map[string]interface{}, format string) map[string]interface{} {
	res := scribeConfig

	if len(policyConfig) > 0 {
		res["select"] = policyConfig["select"]
	}
	LoadCertificates(t, res)
	// LoadFormat(t, format, res)

	debug, found := os.LookupEnv("DEBUG")
	if found && strings.ToLower(debug) == "true" {
		v, err := yaml.Marshal(res)
		t.Log("Values\n", string(v), err) //2DO would love to see this file under the test generated data
	}
	return res
}

func MakeGatekeeperValues() map[string]interface{} {
	return map[string]interface{}{
		"validatingWebhookTimeoutSeconds": 180,
		"enableExternalData":              true,
		"controllerManager": map[string]interface{}{
			"dnsPolicy": "ClusterFirst",
		},
		"audit": map[string]interface{}{
			"dnsPolicy": "ClusterFirst",
		},
	}
}

func WaitForProviderPod(t *testing.T, clientset *kubernetes.Clientset) {
	/* pods, err := clientset.CoreV1().Pods(providerNamespace).List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Equal(t, len(pods.Items), 1)

	w, err := clientset.CoreV1().Pods(providerNamespace).Watch(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	*/
	time.Sleep(10 * time.Second)
}

func GetProviderLogs(t *testing.T, clientset *kubernetes.Clientset) string {
	pods, err := clientset.CoreV1().Pods(providerNamespace).List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err, "client init")
	require.Equal(t, len(pods.Items), 1, "no items")

	request := clientset.CoreV1().Pods(providerNamespace).GetLogs(pods.Items[0].Name, &corev1.PodLogOptions{})

	logs, err := request.Stream(context.Background())
	require.NoError(t, err, "stream request")
	defer logs.Close()

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, logs)
	require.NoError(t, err, "copy logs")

	return buf.String()
}

func ApplyK8sManifest(t *testing.T, clientset *kubernetes.Clientset, image string) error {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-deployment",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(0),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "test-deployment",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "test-deployment",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: image,
						},
					},
				},
			},
		},
	}

	deploymentsClient := clientset.AppsV1().Deployments("default")
	result, err := deploymentsClient.Create(context.TODO(), deployment, metav1.CreateOptions{})

	t.Logf("Deploying manifest %v \n %v", result.Status, err)
	return err
}

func DeleteK8sDeployment(t *testing.T, clientset *kubernetes.Clientset) {
	deploymentClient := clientset.AppsV1().Deployments("default")
	deploymentClient.Delete(context.TODO(), "test-deployment", metav1.DeleteOptions{})
	// require.NoError(t, err)
}
func int32Ptr(i int32) *int32 { return &i }

func PrepareOCIConfigE2E(t *testing.T, defaultAttest string, caPath string, tag string) map[string]interface{} {
	repo, found := os.LookupEnv("SCRIBE_OCI_REPO")
	require.True(t, found, "OCI REPO not found")

	pullSecret, found := os.LookupEnv("IMAGE_PULL_SECRET")
	require.True(t, found, "IMAGE PULL SECRET not found")

	caContent, err := os.ReadFile(caPath)
	require.Nil(t, err)

	return map[string]interface{}{
		"image": map[string]interface{}{
			"imagePullSecrets": string(pullSecret),
			"tag":              tag,
		},
		"scribe": map[string]interface{}{
			"enable": false,
		},
		"cache": map[string]interface{}{
			"enable": false,
		},
		"x509": map[string]interface{}{
			"ca": string(caContent),
		},
		"valint": map[string]interface{}{
			"logger": map[string]interface{}{
				"level": "debug",
			},
			"scribe": map[string]interface{}{
				"auth": map[string]interface{}{
					"enable": false,
				},
				"enable": false,
			},
			"context": map[string]interface{}{
				"context-type": "admission",
			},
			"verify": map[string]interface{}{
				"input-format": "",
				"formats":      "statement",
			},
			"attest": map[string]interface{}{
				"default": defaultAttest,
				"report": map[string]interface{}{
					"disable": true,
				},
				"cocosign": map[string]interface{}{
					"storer": map[string]interface{}{
						"OCI": map[string]interface{}{
							"enable": true,
							"repo":   repo,
						},
					},
				},
			},
		},
	}
}

func PrepareScribeConfigE2E(t *testing.T, defaultAttest string, caPath string, tag string) map[string]interface{} {
	scribeURL, found := os.LookupEnv("SCRIBE_URL")
	require.True(t, found, "Scribe url not found")

	scribeClientID, found := os.LookupEnv("SCRIBE_CLIENT_ID")
	require.True(t, found, "Scribe client id not found")

	pullSecret, found := os.LookupEnv("IMAGE_PULL_SECRET")
	require.True(t, found, "IMAGE PULL SECRET not found")

	scribeClientSecret, found := os.LookupEnv("SCRIBE_CLIENT_SECRET")
	require.True(t, found, "Scribe client secret not found")

	caContent, err := os.ReadFile(caPath)
	require.Nil(t, err)

	return map[string]interface{}{
		"image": map[string]interface{}{
			"imagePullSecrets": string(pullSecret),
			"tag":              tag,
		},
		"scribe": map[string]interface{}{
			"enable":        true,
			"client_id":     scribeClientID,
			"client_secret": scribeClientSecret,
			"url":           scribeURL,
		},
		"cache": map[string]interface{}{
			"enable": false,
		},
		"x509": map[string]interface{}{
			"ca": string(caContent),
		},
		"valint": map[string]interface{}{
			"logger": map[string]interface{}{
				"level": "debug",
			},
			"context": map[string]interface{}{
				"context-type": "admission",
			},
			"verify": map[string]interface{}{
				"input-format": "",
				"formats":      "statement",
			},
			"attest": map[string]interface{}{
				"default": defaultAttest,
			},
		},
	}
}

func BaseFlags(command string, cacheConfig *baseCache.Config, scribeService *api.Config, oci *cocosign_config.OCIStorer, baseConfig string) []string {
	base := []string{command,
		"-vv",
	}

	if cacheConfig.Enable {
		if cacheConfig.OutputDirectory != "" {
			base = append(base, []string{
				"-d", cacheConfig.OutputDirectory,
			}...)
		}

	} else {
		base = append(base, []string{"--cache-enable=false"}...)
	}

	if scribeService.ServiceCfg.Enable {
		scribe := []string{
			"-E",
			"--scribe.url", scribeService.ServiceCfg.URL,
			"--scribe.client-id", scribeService.Auth.ClientID,
			"--scribe.client-secret", scribeService.Auth.ClientSecret,
			"--scribe.login-url", scribeService.Auth.LoginURL,
			"--scribe.auth.audience", scribeService.Auth.Audience,
			"--timeout", "240s", // "--final-artifact",
			"--backoff", "30s",
			"--components", "metadata",
		}
		base = append(base, scribe...)
	}

	if oci.Enable {
		ociFlags := []string{
			"--oci",
		}

		if oci.Repo != "" {
			ociFlags = append(ociFlags, "--oci-repo", oci.Repo)

		}
		base = append(base, ociFlags...)
	}

	if baseConfig == "" {
		base = append(base, "--config", ConfigPath)
	} else {
		base = append(base, "--config", baseConfig)
	}

	return base
}

func PrepareScribeE2E(t *testing.T, command, baseConfig string) []string {
	scribeURL, found := os.LookupEnv("SCRIBE_URL")
	require.True(t, found, "Scribe url not found")

	scribeClientID, found := os.LookupEnv("SCRIBE_CLIENT_ID")
	require.True(t, found, "Scribe client id not found")

	scribeClientSecret, found := os.LookupEnv("SCRIBE_CLIENT_SECRET")
	require.True(t, found, "Scribe client secret not found")

	config := api.Config{
		Auth: api.Auth{
			ClientID:     scribeClientID,
			ClientSecret: scribeClientSecret,
			Enable:       true,
		},
		ServiceCfg: api.ServiceCfg{
			URL:    scribeURL,
			Enable: true,
		},
	}

	return BaseFlags(command, &baseCache.Config{Enable: false}, &config, &cocosign_config.OCIStorer{}, baseConfig)
}

func PrepareOCIE2E(t *testing.T, command, baseConfig string) []string {

	repo, found := os.LookupEnv("SCRIBE_OCI_REPO")
	require.True(t, found, "OCI REPO not found")

	ociConfig := cocosign_config.OCIStorer{
		Enable: true,
		Repo:   repo,
	}

	return BaseFlags(command, &baseCache.Config{}, &api.Config{}, &ociConfig, baseConfig)
}

func PrepareCache(t *testing.T, command, baseConfig string) []string {

	cacheConfig := baseCache.Config{
		Enable: true,
	}

	base := BaseFlags(command, &cacheConfig, &api.Config{}, &cocosign_config.OCIStorer{}, baseConfig)

	switch command {
	case "bom", "slsa":
		return append(base, "-f") // Force overwrite in cache case
	case "bom-compressed":
		return append(base, "-f", "--compress")
	}

	return base
}

func MakeBomFlags(t *testing.T, bom_args []string, format, image, product, productVersion string) []string {
	bom_args_new := append(append([]string(nil), bom_args...), []string{"-o",
		format,
		"--product-key", product,
		"--product-version", productVersion,
		image}...)
	return bom_args_new
}

/*
func ReadFileAndSetEnv(t *testing.T, filename, envVarName string) {
	// Read the file contents
	content, err := ioutil.ReadFile(filename)
	require.Nil(t, err)

	// Set the environment variable with the file contents
	err = os.Setenv(envVarName, string(content))
	require.Nil(t, err)
}
*/

func ConfigureK8s(t *testing.T) *kubernetes.Clientset {
	var kubeconfig string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err)

	clientset, err := kubernetes.NewForConfig(config)
	require.NoError(t, err)

	return clientset
}
