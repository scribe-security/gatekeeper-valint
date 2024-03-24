//go:build e2e_oci
// +build e2e_oci

package integration

import (
	"testing"
	"time"
)

const (
	OCISleepSecond = 10
)

func TestSuccessOCI(t *testing.T) {
	ProviderSuccessTestTable(t, k8sClient(t), &OCIStoreTest{})
	time.Sleep(OCISleepSecond * time.Second)
}

func TestFailOCI(t *testing.T) {
	ProviderFailTestTable(t, k8sClient(t), &OCIStoreTest{})
	time.Sleep(OCISleepSecond * time.Second)
}
