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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/scribe-security/basecli/logger"
	"gopkg.in/yaml.v2"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"

	cocosign_config "github.com/scribe-security/cocosign/signing/config"
	"github.com/scribe-security/gatekeeper-valint/internal/config"
	"github.com/scribe-security/gatekeeper-valint/pkg/glob"
	"github.com/scribe-security/gatekeeper-valint/pkg/utils"
	valintPkg "github.com/scribe-security/valint/pkg"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
)

const (
	apiVersion       = "externaldata.gatekeeper.sh/v1beta1"
	tlsCert          = "/valint-certs/tls.crt"
	tlsKey           = "/valint-certs/tls.key"
	defaultTimeout   = 300 * time.Second
	overhead         = 2 * time.Second
	requestKeyPrefix = "request:"
)

type Metadata struct {
	Labels    map[string]string `yaml:"labels,omitempty" json:"labels,omitempty" mapstructure:"labels"`
	Namespace string            `yaml:"namespace,omitempty" json:"namespace,omitempty" mapstructure:"namespace"`
	Name      string            `yaml:"name,omitempty" json:"name,omitempty" mapstructure:"name"`
}

type AdmissionReview struct {
	Kind     string   `yaml:"kind,omitempty" json:"kind,omitempty" mapstructure:"kind"`
	Metadata Metadata `yaml:"metadata,omitempty" json:"metadata,omitempty" mapstructure:"metadata"`
}

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
		provider.policySelect = policySelect
		utils.SetDryRun(provider.policySelect.DryRun)
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

func (cmd *ProviderCmd) decodeKeys(providerReq externaldata.ProviderRequest) ([]string, map[string]string, string, string, string, error) {
	var images []string
	var labels map[string]string
	var namespace, name, kind string
	var admissionRequest AdmissionReview
	for _, key := range providerReq.Request.Keys {
		if strings.HasPrefix(key, requestKeyPrefix) {
			base := strings.TrimPrefix(key, requestKeyPrefix)
			data, err := base64.StdEncoding.DecodeString(base)
			if err == nil {
				err := json.Unmarshal(data, &admissionRequest)
				if err == nil {
					labels = admissionRequest.Metadata.Labels
					name = admissionRequest.Metadata.Name
					namespace = admissionRequest.Metadata.Namespace
					kind = admissionRequest.Kind
				}
			}
		} else {
			images = append(images, key)
		}
	}

	return images, labels, namespace, name, kind, nil
}

func (cmd *ProviderCmd) Validate(w http.ResponseWriter, req *http.Request) {
	cmd.logger.Info("validating request")

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

	images, labels, namespace, name, kind, err := cmd.decodeKeys(providerRequest)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("unable to decode provider keys: %v", err), w)
		return
	}
	cmd.logger.Infof("evaluating '%s', Labels: %s, Namespace: %s, Name: %s, Kind: %s", images, labels, namespace, name, kind)

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
		for _, image := range images {
			runPolicy(w, image, labels, namespace, name, kind, co, cmd.cfg.Valint, cmd.logger)
		}
	} else if cmd.policySelect != nil {
		if cmd.policySelect.Gate != "" && cmd.cfg.Valint.Context.Gate == "" {
			cmd.cfg.Valint.Context.Gate = cmd.policySelect.Gate
		}

		if cmd.cfg.Valint.Context.Gate != "" {
			cmd.logger.Infof("evaluating gate %s", cmd.cfg.Valint.Context.Gate)
		}

		var policyErrs []error
		var errMsg string
		for _, image := range images {
			errs := runPolicySelectWithError(w, image, labels, namespace, name, kind, co, cmd.policySelect.Apply, cmd.policySelect.Warning, cmd.cfg.Valint, cmd.logger)
			if len(errs) > 0 {
				policyErrs = append(policyErrs, errs...)
				for _, err := range errs {
					cmd.logger.Warnf("Scribe Admission refused '%s' deploy to '%s' with Errors %s", image, namespace, err)
				}
				errMsg = errMsg + fmt.Sprintf(">>>>> Scribe Admission refused '%s' deploy to '%s' with Errors %s<<<<<", image, namespace, errs)
			}
		}

		if len(policyErrs) > 0 {
			utils.SendResponse(nil, errMsg, w)
			return
		}

	} else {
		cmd.logger.Warnf("no policy run on request")
	}

	utils.SendResponse(&results, "", w)
}

func runPolicySelectWithError(w http.ResponseWriter, image string, labels map[string]string, namespace, name, kind string, co []ociremote.Option, applyCfg []config.PolicySelect, dryRun bool, cfg valintPkg.Application, l logger.Logger) []error {
	found := false
	var matchErrs []error
	var policyErrs []error
	var policies []cocosign_config.Policy
	for _, applyPolicy := range applyCfg {
		if len(applyPolicy.Glob) > 0 {
			if applyPolicy.Namespace != "" {
				if applyPolicy.Namespace != namespace {
					l.Debugf("namespace match failed skipping, Found: %s, Expected: %s", namespace, applyPolicy.Namespace)
					continue
				} else {
					l.Infof("namespace '%s' matched for '%s'", namespace, image)
				}
			}

			for _, selectGlob := range applyPolicy.Glob {
				l.Infof("glob matching %s on select regex %s", image, selectGlob)
				if matched, err := glob.Match(selectGlob, image); err != nil {
					l.Debugf("glob match failed skipping, err: %s", image, err)
					matchErrs = append(matchErrs, err)
				} else if matched {
					found = true
					policies = append(policies, applyPolicy.Config.Policies...)
				}
			}
		}
	}

	if !found {
		l.Infof("no policy found for %s deployed to %s namespace , skipping", image, namespace)
	}

	if found && len(policies) > 0 {
		cfg.Attest.Config.Policies = policies
		for _, policy := range policies {
			l.Infof("policy '%s' evaluating for '%s' deployed to '%s' namespace ", policy.NameField, image, namespace)
			for i, rule := range policy.Rules {
				if dryRun {
					if policy.Rules[i].Level != "note" && policy.Rules[i].Level != "warning" {
						if policy.Rules[i].Level == "" {
							l.Infof("Setting '%s' to warning level", rule.NameField)
						} else {
							l.Infof("Downgrade '%s' from '%s' to warning level", rule.NameField, rule.Level)
						}
						policy.Rules[i].Level = "warning"
					}
				}
			}
		}
		err := runPolicyWithError(w, image, labels, namespace, name, kind, co, cfg, l)
		if err != nil {
			policyErrs = append(policyErrs, err)
		} else {
			l.Infof("policies evaluated successfuly for '%s' deployed to '%s' namespace", image, namespace)
		}
	}

	return policyErrs
}

func runPolicyWithError(w http.ResponseWriter, image string, labels map[string]string, namespace, targetName, kind string, co []ociremote.Option, cfg valintPkg.Application, l logger.Logger) error {
	ref, err := name.ParseReference(image)
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

	err = valintPkg.VerifyAdmissionCommand(ref.String(),
		imageID.String(),
		labels, namespace, targetName, kind,
		&cfg,
		l,
		co...,
	)

	if err != nil {
		return err
	}

	return nil
}

func runPolicy(w http.ResponseWriter, image string, labels map[string]string, namespace, targetName, kind string, co []ociremote.Option, cfg valintPkg.Application, l logger.Logger) {
	fmt.Println("valint verify signature for:", image)

	ref, err := name.ParseReference(image)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("ERROR (ParseReference(%q)): %v", image, err), w)
		return
	}

	img, err := ociremote.SignedImage(ref, co...)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("ERROR (Image(%q)): %v", image, err), w)
		return
	}

	imageID, err := img.ConfigName()
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("ERROR (ConfigName(%q)): %v", image, err), w)
		return
	}

	err = valintPkg.VerifyAdmissionCommand(ref.String(),
		imageID.String(),
		labels, namespace, targetName, kind,
		&cfg,
		l,
		co...,
	)

	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("ERROR (VerifyAdmissionImage(%q)): %v", image, err), w)
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
