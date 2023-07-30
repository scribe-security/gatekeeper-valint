package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/scribe-security/gatekeeper-valint/pkg/utils"
	gensbomPkg "github.com/scribe-security/gensbom/pkg"
	"k8s.io/klog/v2"
)

func Handler(w http.ResponseWriter, req *http.Request) {
	// only accept POST requests
	if req.Method != http.MethodPost {
		utils.SendResponse(nil, "only POST is allowed", w)
		return
	}

	// read request body
	requestBody, err := io.ReadAll(req.Body)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("unable to read request body: %v", err), w)
		return
	}

	klog.InfoS("received request", "body", requestBody)

	// parse request body
	var providerRequest externaldata.ProviderRequest
	err = json.Unmarshal(requestBody, &providerRequest)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
		return
	}

	results := make([]externaldata.Item, 0)
	// iterate over all keys
	for _, key := range providerRequest.Request.Keys {
		// Providers should add a caching mechanism to avoid extra calls to external data sources.

		ref, err := name.ParseReference(key)
		if err != nil {
			utils.SendResponse(nil, fmt.Sprintf("ERROR (ParseReference(%q)): %v", key, err), w)
			return
		}

		err := gensbomPkg.VerifyAdmissionImage(c.Image, id.String(), &gensbomConfig, v.logger, ociremote.WithRemoteOptions(
			remote.WithAuthFromKeychain(kc),
			remote.WithAuthFromKeychain(kcScribe),
		))
		// TODO Call valint
	}
	utils.SendResponse(&results, "", w)
}
