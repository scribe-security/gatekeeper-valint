//go:build e2e_scribe
// +build e2e_scribe

package integration

import (
	"testing"
	"time"
)

const (
	scribeSleepSecond = 10
)

func TestSuccessScribe(t *testing.T) {
	ProviderSuccessTestTable(t, k8sClient(t), &ScribeStoreTest{})
	time.Sleep(scribeSleepSecond * time.Second)
}

func TestFailScribe(t *testing.T) {
	ProviderFailTestTable(t, k8sClient(t), &ScribeStoreTest{})
	time.Sleep(scribeSleepSecond * time.Second)
}
