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
	apiVersion     = "externaldata.gatekeeper.sh/v1beta1"
	tlsCert        = "/valint-certs/tls.crt"
	tlsKey         = "/valint-certs/tls.key"
	defaultTimeout = 300 * time.Second
	overhead       = 2 * time.Second
)

type ProviderCmd struct {
	cfg          *config.Application
	ctx          context.Context
	logger       logger.Logger
	policySelect *config.PolicySelectStruct
	timeout      time.Duration
}

func NewProviderCmd(ctx context.Context, cfg *config.Application) (*ProviderCmd, error) {
	l, err := valintPkg.InitCommandLogger("", &cfg.Valint, nil)
	if err != nil {
		return nil, err
	}

	var timeout time.Duration
	newTimeout, err := time.ParseDuration(cfg.Provider.Timeout)
	if err == nil {
		timeout = newTimeout
	} else {
		timeout = defaultTimeout
	}

	provider := &ProviderCmd{
		cfg:     cfg,
		ctx:     ctx,
		logger:  l,
		timeout: timeout,
	}

	var policySelect *config.PolicySelectStruct
	if _, err := os.Stat(cfg.Provider.PolicySelect); err == nil {
		policySelect, err = ReadPolicySelectStruct(cfg.Provider.PolicySelect)
		if err != nil {
			l.Warnf("issue reading policy select list, Err: %s", err)
			return nil, err
		}
		fmt.Println("############### ReadPolicySelectStruct", policySelect.Gate, len(policySelect.Apply))

		provider.policySelect = policySelect
	}

	return provider, nil
}

func (cmd *ProviderCmd) Run() error {

	cmd.logger.Infof("starting HTTPS server on port %d...\n", cmd.cfg.Provider.Port)

	timeoutWithOverhead := cmd.timeout
	if cmd.timeout > 1*time.Second {
		timeoutWithOverhead = timeoutWithOverhead - overhead
	}

	cmd.logger.Infof("timeouts, webhook:%s, process:%s...\n", cmd.timeout, timeoutWithOverhead)

	http.HandleFunc("/validate", processTimeout(cmd.Validate, timeoutWithOverhead))

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cmd.cfg.Provider.Port),
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      cmd.timeout,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if err := srv.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
		return err
	}

	return nil
}

func ReadPolicySelectStruct(file string) (*config.PolicySelectStruct, error) {
	var policySelect config.PolicySelectStruct
	yamlFile, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(yamlFile, &policySelect)
	if err != nil {
		return nil, err
	}

	return &policySelect, nil

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

	ctx, cancel := context.WithTimeout(req.Context(), cmd.timeout)
	defer cancel()

	ro := options.RegistryOptions{}
	co, err := ro.ClientOpts(ctx)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("ERROR: %v", err), w)
		return
	}

	os.Setenv("PULL_BUNDLE", "true")

	if cmd.policySelect == nil ||
		(cmd.policySelect != nil && len(cmd.policySelect.Apply) == 0) {
		// Run Default policy
		for _, key := range providerRequest.Request.Keys {
			runPolicy(w, key, co, cmd.cfg.Valint, cmd.logger)
		}
	} else if cmd.policySelect != nil {
		fmt.Println("###################### GATE ", cmd.policySelect.Gate, cmd.cfg.Valint.Context.Gate)
		if cmd.policySelect.Gate != "" && cmd.cfg.Valint.Context.Gate == "" {
			cmd.cfg.Valint.Context.Gate = cmd.policySelect.Gate
		}

		if cmd.cfg.Valint.Context.Gate != "" {
			cmd.logger.Infof("evaluating gate %s", cmd.cfg.Valint.Context.Gate)
		}

		for _, key := range providerRequest.Request.Keys {
			err := runPolicySelectWithError(w, key, co, cmd.policySelect.Apply, cmd.cfg.Valint, cmd.logger)
			if err != nil {
				utils.SendResponse(nil, fmt.Sprintf("ERROR (VerifyAdmissionImage(%q)): %v", key, err), w)
				return
			}
		}
	} else {
		cmd.logger.Warnf("no policy run on request")
	}

	utils.SendResponse(&results, "", w)
}

func runPolicySelectWithError(w http.ResponseWriter, key string, co []ociremote.Option, applyCfg []config.PolicySelect, cfg valintPkg.Application, l logger.Logger) error {
	found := false
	var matchErrs []error
	for _, applyPolicy := range applyCfg {
		if len(applyPolicy.Glob) > 0 {
			for _, selectGlob := range applyPolicy.Glob {
				l.Infof("matching %s on select regex %s", key, selectGlob)
				if matched, err := glob.Match(selectGlob, key); err != nil {
					l.Debugf("match failed skipping, err: %s", key, err)
					matchErrs = append(matchErrs, err)
				} else if matched {
					found = true
					for _, policy := range applyPolicy.Config.Policies {
						l.Infof("policy %s evaluating for %s", policy.NameField, key)
					}

					cfg.Attest.Config.Policies = append(cfg.Attest.Config.Policies, applyPolicy.Config.Policies...)
					err := runPolicyWithError(w, key, co, cfg, l)
					if err != nil {
						return err
					}
					break
				}
			}
		}
	}
	if !found {
		l.Infof("no policy found for image %s, skipping", key)
	} else {
		l.Infof("policies evaluated successfuly for %s", key)
	}

	return nil
}

func runPolicyWithError(w http.ResponseWriter, key string, co []ociremote.Option, cfg valintPkg.Application, l logger.Logger) error {
	ref, err := name.ParseReference(key)
	if err != nil {
		return err
	}

	img, err := ociremote.SignedImage(ref, co...)
	if err != nil {
		return err
	}

	imageID, err := img.ConfigName()
	if err != nil {
		return err
	}

	err = valintPkg.VerifyAdmissionImage(ref.String(),
		imageID.String(),
		&cfg,
		l,
		co...,
	)

	if err != nil {
		return err
	}

	return nil
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
