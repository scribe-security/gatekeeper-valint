package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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
)

/* func PrepareScribeE2E(t *testing.T) []string {
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
}
*/

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

func HelmInstall(t *testing.T, chart string, values string) {
	tests := []struct {
		name string
	}{
		{
			name: "valid-deployment",
		},
	}

	for _, test := range tests {
		startTime := time.Now()

		t.Run(test.name, func(t *testing.T) {

			for _, name := range test.name {
				t.Log("###### Testing ", name, "######")
				var err error
				require.NoError(t, err)
			}

		})
		endTime := time.Now()
		elapsed := endTime.Sub(startTime)
		fmt.Printf("Elapsed: %s\n", elapsed)
	}
}

func InstallGatekeeper(t *testing.T) {
	settings := cli.New()

	actionConfig := new(action.Configuration)
	err := actionConfig.Init(settings.RESTClientGetter(), gatekeeperNamespace, os.Getenv("HELM_DRIVER"), t.Logf)
	require.NoError(t, err)

	client := action.NewInstall(actionConfig)
	client.RepoURL = "https://open-policy-agent.github.io/gatekeeper/charts"
	client.ReleaseName = "gatekeeper"
	client.CreateNamespace = true
	client.NameTemplate = "gatekeeper"
	client.Namespace = gatekeeperNamespace

	chartPath, err := client.LocateChart("gatekeeper", settings)
	require.NoError(t, err)

	chart, err := loader.Load(chartPath)
	require.NoError(t, err)

	vals := MakeGatekeeperValues()
	r, err := client.Run(chart, vals)
	require.NoError(t, err)

	t.Logf("Deployed Gatekeeper at %v", r.Namespace)
}

func InstallProvider(t *testing.T) {
	settings := cli.New()

	settings.Debug = true

	actionConfig := new(action.Configuration)
	err := actionConfig.Init(settings.RESTClientGetter(), providerNamespace, os.Getenv("HELM_DRIVER"), t.Logf)
	require.NoError(t, err)

	client := action.NewInstall(actionConfig)
	client.ReleaseName = "gatekeeper-valint"
	client.CreateNamespace = true
	client.NameTemplate = "gatekeeper-valint"
	client.Namespace = providerNamespace
	chartPath, err := client.LocateChart("../../charts/gatekeeper-valint", settings)
	require.NoError(t, err)

	chart, err := loader.Load(chartPath)
	require.NoError(t, err)

	vals := LoadCertificates(t)
	r, err := client.Run(chart, vals)
	require.NoError(t, err)

	t.Logf("Deployed Provider at %v", r.Namespace)
}

func GenerateCertificates(t *testing.T) {
	cmd := []string{"./generate-tls-cert.sh"}
	_, _, err := RunCmd(t, cmd)
	require.NoError(t, err)
}

func TestInitial(t *testing.T) {
	InstallGatekeeper(t)
	GenerateCertificates(t)
	InstallProvider(t)

	clientset := ConfigureK8s(t)
	WaitForProviderPod(t, clientset)
	logs := GetProviderLogs(t, clientset)

	t.Logf("%v", logs)
}

func RunCmd(t testing.TB, cmd []string) (*exec.Cmd, string, error) {
	HEAD := cmd[0]
	CMD := cmd[1:]
	execCmd := exec.Command(HEAD, CMD...)
	execCmd.Env = os.Environ()

	out, err := execCmd.CombinedOutput()
	if err != nil {
		t.Logf("[COMMAND] exec fail, Command: %v", cmd)
	} else {
		t.Logf("[COMMAND] exec success, Command: %v", cmd)
	}
	return execCmd, string(out), err
}

func LoadCertificates(t *testing.T) map[string]interface{} {
	res := make(map[string]interface{})
	ca, err := os.ReadFile("../../certs/ca.crt")
	require.NoError(t, err)

	crt, err := os.ReadFile("../../certs/tls.crt")
	require.NoError(t, err)

	key, err := os.ReadFile("../../certs/tls.key")
	require.NoError(t, err)

	res["certs"] = make(map[string]interface{})
	res["certs"].(map[string]interface{})["caBundle"] = base64.StdEncoding.EncodeToString(ca)
	res["certs"].(map[string]interface{})["tlsCrt"] = string(crt)
	res["certs"].(map[string]interface{})["tlsKey"] = string(key)
	return res
}

func MakeGatekeeperValues() map[string]interface{} {
	res := make(map[string]interface{})

	res["validatingWebhookTimeoutSeconds"] = 30
	res["enableExternalData"] = true
	res["controllerManager"] = make(map[string]interface{})
	res["controllerManager"].(map[string]interface{})["dnsPolicy"] = "ClusterFirst"

	res["audit"] = make(map[string]interface{})
	res["audit"].(map[string]interface{})["dnsPolicy"] = "ClusterFirst"

	return res
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
