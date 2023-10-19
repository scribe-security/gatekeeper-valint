package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	// "helm.sh/helm/v3/pkg/release"
)

var (
	gatekeeperNamespace = "gatekeeper-system"
	providerNamespace   = "gatekeeper-valint"
	ConfigPath          = "testdata/test.yaml"
	ConfigPathEnv       = "testdata/test_env.yaml"
)

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

func HelmInstallTable(t *testing.T, clientset *kubernetes.Clientset) {
	tests := []struct {
		name          string
		image         string
		expectedError string
		bomFlags      []string
		valintConfig  map[string]interface{}
		scribeConfig  map[string]interface{}
	}{
		// {
		// 	name:          "No evidence deployment",
		// 	image:         "scribesecuriy.jfrog.io/scribe-docker-public-local/test/gensbom_alpine_input:latest",
		// 	expectedError: "Err: no evidence found",
		// },
		// {
		// 	name:          "Scribe no evidence deployment",
		// 	image:         "scribesecuriy.jfrog.io/scribe-docker-public-local/test/gensbom_alpine_input:latest",
		// 	expectedError: "Err: no evidence found",
		// 	scribeConfig:  MakeScribeConfig(t),
		// },
		{
			name:          "Scribe evidence deployment",
			image:         "scribesecuriy.jfrog.io/scribe-docker-public-local/test/gensbom_alpine_input:latest",
			expectedError: "",
			bomFlags:      MakeBomFlags(t, PrepareScribeE2E(t, "bom", ConfigPath), "statement", "scribesecuriy.jfrog.io/scribe-docker-public-local/test/gensbom_alpine_input:latest"),
			scribeConfig:  MakeScribeConfig(t),
			valintConfig:  MakeValintScribeConfig(t),
		},
	}

	for _, test := range tests {
		startTime := time.Now()

		t.Run(test.name, func(t *testing.T) {

			t.Log("###### Testing ", test.name, "######")
			InstallGatekeeper(t)
			InstallProvider(t, test.scribeConfig)

			if test.bomFlags != nil {
				t.Log("###### Running ", test.bomFlags, "######")
				_, out, err := runCmd(t, test.bomFlags...)
				t.Logf(out)
				require.NoError(t, err)
			}

			WaitForProviderPod(t, clientset)

			err := ApplyK8sManifest(t, clientset, test.image)

			logs := GetProviderLogs(t, clientset)
			t.Logf("%v", logs)

			if test.expectedError == "" {
				require.NoError(t, err)
			} else {
				require.True(t, strings.Contains(err.Error(), test.expectedError))
			}

			DeleteK8sDeployment(t, clientset)
			UninstallProvider(t)
			UninstallGatekeeper(t)
		})
		endTime := time.Now()
		elapsed := endTime.Sub(startTime)
		fmt.Printf("Elapsed: %s\n", elapsed)
	}
}

func HelmUninstall(t *testing.T, namespace string, releaseName string) {
	settings := cli.New()

	actionConfig := new(action.Configuration)
	err := actionConfig.Init(settings.RESTClientGetter(), namespace, os.Getenv("HELM_DRIVER"), t.Logf)
	require.NoError(t, err)

	client := action.NewUninstall(actionConfig)
	_, err = client.Run(releaseName)
	require.NoError(t, err)
}

func HelmInstall(t *testing.T, namespace string, repo string, chart string, releaseName string, vals map[string]interface{}) {
	settings := cli.New()

	actionConfig := new(action.Configuration)
	err := actionConfig.Init(settings.RESTClientGetter(), namespace, os.Getenv("HELM_DRIVER"), t.Logf)
	require.NoError(t, err)

	client := action.NewInstall(actionConfig)
	client.CreateNamespace = true
	client.ReleaseName = releaseName
	client.NameTemplate = releaseName
	client.Namespace = namespace
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

	_, err = client.Run(helmChart, vals)
	require.NoError(t, err)
}

func InstallGatekeeper(t *testing.T) {
	HelmInstall(t, gatekeeperNamespace, "https://open-policy-agent.github.io/gatekeeper/charts",
		"gatekeeper", "gatekeeper", MakeGatekeeperValues())
}

func UninstallGatekeeper(t *testing.T) {
	HelmUninstall(t, gatekeeperNamespace, "gatekeeper")
}

func InstallProvider(t *testing.T, scribeConfig map[string]interface{}) {
	HelmInstall(t, providerNamespace, "../../charts/gatekeeper-valint",
		"gatekeeper-valint", "gatekeeper-valint", MakeProviderValues(t, scribeConfig))
}

func UninstallProvider(t *testing.T) {
	HelmUninstall(t, providerNamespace, "gatekeeper-valint")
}

func GenerateCertificates(t *testing.T) {
	cmd := []string{"./generate-tls-cert.sh"}
	_, _, err := RunCmd(t, cmd)
	require.NoError(t, err)
}

func TestInitial(t *testing.T) {
	GenerateCertificates(t)

	clientset := ConfigureK8s(t)

	HelmInstallTable(t, clientset)
}

func LoadCertificates(t *testing.T, values map[string]interface{}) {
	ca, err := os.ReadFile("../../certs/ca.crt")
	require.NoError(t, err)

	crt, err := os.ReadFile("../../certs/tls.crt")
	require.NoError(t, err)

	key, err := os.ReadFile("../../certs/tls.key")
	require.NoError(t, err)

	values["certs"] = map[string]interface{}{
		"caBundle": base64.StdEncoding.EncodeToString(ca),
		"tlsCrt":   string(crt),
		"tlsKey":   string(key),
	}
}

func MakeProviderValues(t *testing.T, scribeConfig map[string]interface{}) map[string]interface{} {
	res := make(map[string]interface{})

	LoadCertificates(t, res)
	res["scribe"] = scribeConfig

	return res
}

func MakeGatekeeperValues() map[string]interface{} {
	return map[string]interface{}{
		"validatingWebhookTimeoutSeconds": 30,
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
	require.NoError(t, err)
	require.Equal(t, len(pods.Items), 1)

	request := clientset.CoreV1().Pods(providerNamespace).GetLogs(pods.Items[0].Name, &corev1.PodLogOptions{})

	logs, err := request.Stream(context.Background())
	require.NoError(t, err)
	defer logs.Close()

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, logs)
	require.NoError(t, err)

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

func MakeScribeConfig(t *testing.T) map[string]interface{} {
	// scribeURL, found := os.LookupEnv("SCRIBE_URL")
	// require.True(t, found, "Scribe url not found")

	scribeClientID, found := os.LookupEnv("SCRIBE_CLIENT_ID")
	require.True(t, found, "Scribe client id not found")

	scribeClientSecret, found := os.LookupEnv("SCRIBE_CLIENT_SECRET")
	require.True(t, found, "Scribe client secret not found")

	// scribeCLientLoginURL, found := os.LookupEnv("SCRIBE_LOGIN_URL")
	// require.True(t, found, "Scribe client login url")

	// scribeClientAudience, found := os.LookupEnv("SCRIBE_AUDIENCE")
	// require.True(t, found, "Scribe client login audience")

	return map[string]interface{}{
		"client_id":     scribeClientID,
		"client_secret": scribeClientSecret,
		"enable":        true,
	}
}

func MakeValintScribeConfig(t *testing.T) map[string]interface{} {
	return map[string]interface{}{
		"config": map[string]interface{}{
			"logger": map[string]interface{}{
				"level": "debug",
			},
			"verify": map[string]interface{}{
				"input-format": "statement",
			},
			"attest": map[string]interface{}{
				"default": "x509-env",
			},
			"cocosign": map[string]interface{}{
				"storer": map[string]interface{}{
					"OCI": map[string]interface{}{
						"enable": false,
					},
					"scribe": map[string]interface{}{
						"enable": true,
					},
				},
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

	scribeCLientLoginURL, found := os.LookupEnv("SCRIBE_LOGIN_URL")
	require.True(t, found, "Scribe client login url")

	scribeClientAudience, found := os.LookupEnv("SCRIBE_AUDIENCE")
	require.True(t, found, "Scribe client login audience")

	config := api.Config{
		Auth: api.Auth{
			LoginURL:     scribeCLientLoginURL,
			ClientID:     scribeClientID,
			ClientSecret: scribeClientSecret,
			Audience:     scribeClientAudience,
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

func MakeBomFlags(t *testing.T, bom_args []string, format, image string) []string {
	bom_args_new := append(append([]string(nil), bom_args...), []string{"-o", format, image}...)
	return bom_args_new
}
