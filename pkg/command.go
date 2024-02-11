// Copyright The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pkg

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/scribe-security/basecli/logger"
	"gopkg.in/yaml.v2"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"

	"github.com/scribe-security/gatekeeper-valint/internal/config"
	"github.com/scribe-security/gatekeeper-valint/pkg/glob"
	"github.com/scribe-security/gatekeeper-valint/pkg/utils"
	valintPkg "github.com/scribe-security/valint/pkg"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

const (
	apiVersion = "externaldata.gatekeeper.sh/v1beta1"
	tlsCert    = "/valint-certs/tls.crt"
	tlsKey     = "/valint-certs/tls.key"
	timeout    = 30 * time.Second
)

type ProviderCmd struct {
	cfg              *config.Application
	ctx              context.Context
	logger           logger.Logger
	policySelectList config.PolicySelectList
}

func NewProviderCmd(ctx context.Context, cfg *config.Application) (*ProviderCmd, error) {
	l, err := valintPkg.InitCommandLogger("", &cfg.Valint, nil)
	if err != nil {
		return nil, err
	}

	var policySelectList config.PolicySelectList
	if _, err := os.Stat(cfg.Provider.PolicyMap); err == nil {
		policySelectList, err = ReadPolicySelectList(cfg.Provider.PolicyMap)
		if err != nil {
			l.Warnf("issue reading policy select list, Err: %s", err)
			return nil, err
		}
	}

	return &ProviderCmd{
		cfg:              cfg,
		ctx:              ctx,
		policySelectList: policySelectList,
		logger:           l,
	}, nil
}

func (cmd *ProviderCmd) Run() error {

	fmt.Printf("starting HTTPS server on port %d...\n", cmd.cfg.Provider.Port)

	http.HandleFunc("/validate", processTimeout(cmd.Validate, timeout))

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cmd.cfg.Provider.Port),
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if err := srv.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
		return err
	}

	return nil
}

func ReadPolicySelectList(file string) (config.PolicySelectList, error) {
	var policyMap config.PolicySelectList
	yamlFile, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(yamlFile, &policyMap)
	if err != nil {
		return nil, err
	}

	return policyMap, nil

}

func (cmd *ProviderCmd) Validate(w http.ResponseWriter, req *http.Request) {
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

	// parse request body
	var providerRequest externaldata.ProviderRequest
	err = json.Unmarshal(requestBody, &providerRequest)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
		return
	}

	results := make([]externaldata.Item, 0)

	ctx, cancel := context.WithTimeout(req.Context(), timeout)
	defer cancel()

	ro := options.RegistryOptions{}
	co, err := ro.ClientOpts(ctx)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("ERROR: %v", err), w)
		return
	}

	os.Setenv("PULL_BUNDLE", "true")

	if len(cmd.policySelectList) == 0 {
		// Run Default policy
		for _, key := range providerRequest.Request.Keys {
			runPolicy(w, key, co, cmd.cfg.Valint, cmd.logger)
		}
	} else {
		var matchErrs []error
		for _, key := range providerRequest.Request.Keys {
			found := false
			for _, selectPolicy := range cmd.policySelectList {
				if selectPolicy.Glob != "" {
					fmt.Printf("glob match, Glob: %s, Key %s\n", selectPolicy.Glob, key)
					if matched, err := glob.Match(selectPolicy.Glob, key); err != nil {
						fmt.Println("glob not found", err)
						matchErrs = append(matchErrs, err)
					} else if matched {
						found = true
						fmt.Println("glob match found")
						cmd.cfg.Valint.Attest.Config.Policies = selectPolicy.Config.Policies
						runPolicy(w, key, co, cmd.cfg.Valint, cmd.logger)
					}
				}
			}
			if !found {
				fmt.Println("no policy found for image", key)
			}
		}
	}

	utils.SendResponse(&results, "", w)
}

func runPolicy(w http.ResponseWriter, key string, co []ociremote.Option, cfg valintPkg.Application, l logger.Logger) {
	fmt.Println("valint verify signature for:", key)

	ref, err := name.ParseReference(key)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("ERROR (ParseReference(%q)): %v", key, err), w)
		return
	}

	img, err := ociremote.SignedImage(ref, co...)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("ERROR (Image(%q)): %v", key, err), w)
		return
	}

	imageID, err := img.ConfigName()
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("ERROR (ConfigName(%q)): %v", key, err), w)
		return
	}

	err = valintPkg.VerifyAdmissionImage(ref.String(),
		imageID.String(),
		&cfg,
		l,
		co...,
	)

	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("ERROR (VerifyAdmissionImage(%q)): %v", key, err), w)
		return
	}
}

func processTimeout(h http.HandlerFunc, duration time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), duration)
		defer cancel()

		r = r.WithContext(ctx)

		processDone := make(chan bool)
		go func() {
			h(w, r)
			processDone <- true
		}()

		select {
		case <-ctx.Done():
			utils.SendResponse(nil, "operation timed out", w)
		case <-processDone:
		}
	}
}
