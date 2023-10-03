package integration

import (
	// "context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	// metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	chartPath, err := client.LocateChart("https://open-policy-agent.github.io/gatekeeper/charts/", settings)
	require.NoError(t, err)

	chart, err := loader.Load(chartPath)
	require.NoError(t, err)

	_, err = client.Run(chart, nil)
	require.NoError(t, err)
}

func GenerateCertificates(t *testing.T) {
	cmd := []string{"../../scripts/generate-tls-cert.sh"}
	RunCmd(t, cmd)
}

func TestInitial(t *testing.T) {
	// clientset := ConfigureK8s(t)
	// InstallGatekeeper(t)
	GenerateCertificates(t)
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
		t.Logf("[COMMAND] exec success, Command: %v, %v", cmd, string(out))
	}
	return execCmd, string(out), err
}
