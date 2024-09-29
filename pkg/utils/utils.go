package utils

import (
	"encoding/json"
	"net/http"

	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"k8s.io/klog/v2"
)

const (
	apiVersion = "externaldata.gatekeeper.sh/v1beta1"
	kind       = "ProviderResponse"
)

var (
	DryRunGlobal = false
)

func SetDryRun(dryRun bool) {
	if dryRun {
		klog.InfoS("Running in dry run mode")
	}
	DryRunGlobal = dryRun
}

func SendResponseWithWarning(results *[]externaldata.Item, systemErr string, respCode int, isMutation bool, w http.ResponseWriter, warning bool) error {
	if warning {
		klog.InfoS("Warning Policy - Pre-approve admission")
		if systemErr != "" {
			klog.Errorf("Warning Policy - Pre-approve admission: %s", systemErr)
		}
		klog.Infof("Response Admission passed")
		emptyResults := make([]externaldata.Item, 0)
		return SendResponse(&emptyResults, "", http.StatusOK, false, w)
	}

	return SendResponse(results, systemErr, respCode, isMutation, w)
}

// sendResponse sends back the response to Gatekeeper.
func SendResponse(results *[]externaldata.Item, systemErr string, respCode int, isMutation bool, w http.ResponseWriter) error {
	emptyResults := make([]externaldata.Item, 0)
	if DryRunGlobal && results == nil && systemErr != "" {
		klog.InfoS("dry run mocking success, Failed with", systemErr)
		if results == nil {
			results = &emptyResults
		}
	}

	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       kind,
		Response: externaldata.Response{
			Idempotent: isMutation, // mutation requires idempotent results
		},
	}

	if results != nil {
		response.Response.Items = *results
	} else {
		klog.Infof("Response system error %v %d", response, respCode)
		response.Response.SystemError = systemErr
	}

	w.WriteHeader(respCode)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		klog.ErrorS(err, "unable to encode response")
		klog.Infof("Response %v", response)
		return err
	}

	return nil
}

func SendResponseWithError(results *[]externaldata.Item, systemErr string, w http.ResponseWriter) error {
	emptyResults := make([]externaldata.Item, 0)
	if DryRunGlobal && results == nil && systemErr != "" {
		klog.InfoS("dry run mocking success, Failed with", systemErr)
		if results == nil {
			results = &emptyResults
		}
	}

	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       kind,
		Response: externaldata.Response{
			Idempotent: true, // mutation requires idempotent results
		},
	}

	if results != nil {
		response.Response.Items = *results
	} else {
		response.Response.SystemError = systemErr
	}

	klog.InfoS("sending response", "response", response)

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		klog.ErrorS(err, "unable to encode response")
		return err
	}

	return nil
}
