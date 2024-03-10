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

	cocosign_attestation "github.com/scribe-security/cocosign/attestation"
	cocosign_config "github.com/scribe-security/cocosign/signing/config"

	"github.com/scribe-security/cocosign/storer/evidence"
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
	useTag := cmd.policySelect.UseTag
	ignoreImageID := cmd.policySelect.IgnoreImageID
	images, labels, namespace, name, kind, err := cmd.decodeKeys(providerRequest)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("unable to decode provider keys: %v", err), w)
		return
	}
	cmd.logger.Infof("evaluating (%d) '%s', Labels: %s, Namespace: %s, Name: %s, Kind: %s", len(images), images, labels, namespace, name, kind)

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
			runPolicy(w, image, labels, namespace, name, kind, useTag, ignoreImageID, co, cmd.cfg.Valint, cmd.logger)
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

			errs := runPolicySelectWithError(w, image, labels, namespace, name, kind, useTag, ignoreImageID, co, cmd.policySelect.Apply, cmd.policySelect.Warning, cmd.cfg.Valint, cmd.logger)
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

func SearchAdmissionImages(image string, labels map[string]string, namespace, targetName, kind, productKey, productVersion string, useTag, ignoreImageID bool, cfg *valintPkg.Application, l logger.Logger, remoteOpts ...ociremote.Option) ([]evidence.Referable, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, err
	}

	img, err := ociremote.SignedImage(ref, remoteOpts...)
	if err != nil {
		return nil, err
	}

	imageID, err := img.ConfigName()
	if err != nil {
		return nil, err
	}

	return valintPkg.SearchAdmissionImages(ref.String(),
		imageID.String(),
		labels, namespace, targetName, kind,
		productKey, productVersion,
		useTag, ignoreImageID,
		cfg,
		l,
		remoteOpts...,
	)
}

func SearchAdmissionImage(image string, labels map[string]string, namespace, targetName, kind, productKey, productVersion string, useTag, ignoreImageID bool, cfg *valintPkg.Application, l logger.Logger, remoteOpts ...ociremote.Option) (evidence.ContextHeader, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, err
	}

	img, err := ociremote.SignedImage(ref, remoteOpts...)
	if err != nil {
		return nil, err
	}

	imageID, err := img.ConfigName()
	if err != nil {
		return nil, err
	}

	return valintPkg.SearchAdmissionImage(ref.String(),
		imageID.String(),
		labels, namespace, targetName, kind,
		productKey, productVersion,
		useTag, ignoreImageID,
		cfg,
		l,
		remoteOpts...,
	)
}

func setFilterBy(latestRef evidence.Referable, matchedGlob config.PolicySelect, policyName string, l logger.Logger) {
	if matchedGlob.Policy.Defaults.Match == nil {
		matchedGlob.Policy.Defaults.Match = make(map[string]interface{})
	}

	// Set policy evidence scope
	for _, filterBy := range matchedGlob.FilterBy {
		switch filterBy {
		case "pipeline":
			if latestRef != nil {
				l.Infof("[policy-select] [%s] Setting Build from target, Workflow %s, RunID: %s", policyName, latestRef.Context().ContextWorkflow(), latestRef.Context().ContextRunID())
				if latestRef.Context().ContextRunID() != "" {
					matchedGlob.Policy.Defaults.Match["run_id"] = latestRef.Context().ContextRunID()
				}
				if latestRef.Context().ContextWorkflow() != "" {
					matchedGlob.Policy.Defaults.Match["workflow"] = latestRef.Context().ContextWorkflow()
				}

				matchedGlob.Policy.Defaults.FilterBy = append(matchedGlob.Policy.Defaults.FilterBy, "pipeline")
			}
		case "product":
			if matchedGlob.ProductKey != "" {
				l.Infof("[policy-select] [%s] Setting Product '%s'", policyName, matchedGlob.ProductKey)

				matchedGlob.Policy.Defaults.Match["name"] = matchedGlob.ProductKey
				// os.Setenv("PRODUCT_KEY", matchedGlob.ProductKey)
				matchedGlob.Policy.Defaults.FilterBy = append(matchedGlob.Policy.Defaults.FilterBy, "product")
			} else {
				if latestRef != nil && latestRef.Context().Name() != "" {
					if latestRef.Context().Name() != "" {
						l.Infof("[policy-select] [%s] Setting Product from target '%s'", latestRef.Context().Name())
						// os.Setenv("PRODUCT_KEY", latestRef.Context().Name())
						matchedGlob.Policy.Defaults.Match["name"] = latestRef.Context().Name()
					}
					matchedGlob.Policy.Defaults.FilterBy = append(matchedGlob.Policy.Defaults.FilterBy, "product")
				}
			}
		case "target":
			l.Infof("[policy-select] [%s] Setting Target '%s'", policyName, matchedGlob.ProductKey)
			if latestRef != nil && latestRef.Context().ContextVersion() != "" {
				l.Infof("[policy-select] [%s] Setting Target '%s'", policyName, latestRef.Context().ContextVersion())
			}
			matchedGlob.Policy.Defaults.FilterBy = append(matchedGlob.Policy.Defaults.FilterBy, "target")
		default:
		}
	}
}

func selectGlobPolicies(image, namespace, targetName, kind string, applyCfg []config.PolicySelect, l logger.Logger) ([]config.PolicySelect, []error) {
	var matchErrs []error
	var matchedGlobPolicies []config.PolicySelect

	for _, applyPolicy := range applyCfg {
		if len(applyPolicy.Glob) > 0 {
			if applyPolicy.Namespace != "" {
				if applyPolicy.Namespace != namespace {
					matchErr := fmt.Errorf("namespace match failed skipping, Found: %s, Expected: %s", namespace, applyPolicy.Namespace)
					matchErrs = append(matchErrs, matchErr)
					l.Infof("[policy-select] Image '%s' Skipped '%s', %s", image, applyPolicy.Policy.NameField, matchErr)
					continue
				} else {
					l.Infof("[policy-select] namespace '%s' matched for '%s'", namespace, image)
				}
			}

			for _, selectGlob := range applyPolicy.Glob {
				l.Infof("glob matching %s on select regex %s", image, selectGlob)
				if matched, err := glob.Match(selectGlob, image); err != nil {
					l.Debugf("[policy-select] glob match failed skipping, err: %s", image, err)
					l.Infof("[policy-select] Image '%s' Skipped '%s', %s", image, applyPolicy.Policy.NameField)
					matchErrs = append(matchErrs, err)
					continue
				} else if matched {
					matchedGlobPolicies = append(matchedGlobPolicies, applyPolicy)
				}
			}
		}
	}

	return matchedGlobPolicies, matchErrs
}

func getLatest(policyName string, imageRefs []evidence.Referable, productToRef map[string][]evidence.Referable, matchedGlob config.PolicySelect, l logger.Logger) evidence.Referable {
	var latestRef evidence.Referable
	var err error

	// Get latest ref by product in global.
	if matchedGlob.ProductKey != "" {
		matchedRefs, ok := productToRef[matchedGlob.ProductKey]
		if ok {
			latestRef, err = cocosign_attestation.LatestRefSingle(matchedRefs, l)
			if err != nil {
				l.Infof("[policy-select] [%s] no ref found %s in product '%s', %s", policyName, matchedGlob.ProductKey, err)
			}
		}
	} else {
		latestRef, err = cocosign_attestation.LatestRefSingle(imageRefs, l)
		if err != nil {
			l.Infof("[policy-select] [%s] no ref found, %s", policyName, err)
		}
	}

	return latestRef
}

func mapProductToRef(image string, imageRefs []evidence.Referable, l logger.Logger) map[string][]evidence.Referable {
	productToRef := make(map[string][]evidence.Referable)
	for _, r := range imageRefs {
		if r.Context().Name() != "" {
			l.Debugf("[policy-select] For '%s' found on '%s'", image, r.Context().Name())
			val, ok := productToRef[r.Context().Name()]
			if ok {
				productToRef[r.Context().Name()] = append(val, r)
			} else {
				productToRef[r.Context().Name()] = []evidence.Referable{r}
			}
		}
	}

	return productToRef
}

func runPolicySelectWithError(w http.ResponseWriter, image string, labels map[string]string, namespace, targetName, kind string, useTag, ignoreImageID bool, co []ociremote.Option, applyCfg []config.PolicySelect, dryRun bool, cfg valintPkg.Application, l logger.Logger) []error {
	var matchErrs []error
	var policyErrs []error
	var policies []cocosign_config.PolicyFile
	var matchedGlobPolicies []config.PolicySelect
	var matchedProductPolicies []config.PolicySelect

	matchedGlobPolicies, errs := selectGlobPolicies(image, namespace, targetName, kind, applyCfg, l)
	if len(errs) > 0 {
		matchErrs = append(matchErrs, errs...)
	}
	if len(matchedGlobPolicies) == 0 {
		l.Infof("[policy-select] no policy found for %s deployed to %s namespace , skipping", image, namespace)
	}

	if len(matchedGlobPolicies) > 0 {
		imageRefs, err := SearchAdmissionImages(image,
			labels, namespace, targetName, kind,
			"", "",
			useTag, ignoreImageID,
			&cfg,
			l,
			co...,
		)

		if err != nil {
			l.Infof("[policy-select] image search '%s' Error, %s", image, err)
		}

		for _, r := range imageRefs {
			if r.Context().Name() != "" {
				l.Infof("Searched found '%s' on '%s'", image, r.Context().Name())
			} else {
				l.Infof("Searched found '%s' with no product (%s)", image, r.Ref())
			}
		}

		productToRef := mapProductToRef(image, imageRefs, l)

		for _, matchedGlob := range matchedGlobPolicies {
			policyName := matchedGlob.Policy.NameField
			latestRef := getLatest(policyName, imageRefs, productToRef, matchedGlob, l)

			// Skip Policy when image not found in product.
			if matchedGlob.ProductKey != "" && latestRef == nil {
				l.Infof("[policy-select] [%s] skipping Policy '%s' image not found in product '%s'", policyName, image, matchedGlob.ProductKey)
				continue
			}

			if latestRef != nil {
				v, _ := json.MarshalIndent(latestRef.Context(), "", " ")
				l.Debugf("[policy-select] [%s] Using Policy '%s' image with Context: %s", policyName, image, string(v))
			} else {
				l.Infof("[policy-select] [%s] continue with out scope", policyName)
			}

			if matchedGlob.Policy.Defaults.Match == nil {
				matchedGlob.Policy.Defaults.Match = make(map[string]interface{})
			}

			// Set policy evidence scope
			setFilterBy(latestRef, matchedGlob, policyName, l)

			matchedProductPolicies = append(matchedProductPolicies, matchedGlob)
		}
	}

	if len(matchedProductPolicies) > 0 {
		cfg.Attest.Config.Policies = []cocosign_config.Policy{}
		for _, matched := range matchedProductPolicies {
			policies = append(policies, matched.Policy)
		}

		cocosign_config.ImportPolicyCfgs(&cfg.Attest.Config, policies)
		for _, policy := range policies {
			l.Infof("[policy-select] '%s' evaluating for '%s' in the '%s' namespace ", policy.NameField, image, namespace)
			for i, rule := range policy.Rules {
				if dryRun {
					if policy.Rules[i].Level != "note" && policy.Rules[i].Level != "warning" {
						if policy.Rules[i].Level == "" {
							l.Infof("[policy-select] Setting '%s' to warning level", rule.NameField)
						} else {
							l.Infof("[policy-select] Downgrade '%s' from '%s' to warning level", rule.NameField, rule.Level)
						}
						policy.Rules[i].Level = "warning"
					}
				}
			}
		}
		err := runPolicyWithError(w, image, labels, namespace, targetName, kind, useTag, ignoreImageID, co, cfg, l)
		if err != nil {
			policyErrs = append(policyErrs, err)
		} else {
			l.Infof("[policy-select] policies evaluated successfuly for '%s' deployed to '%s' namespace", image, namespace)
		}
	}

	return policyErrs
}

func runPolicyWithError(w http.ResponseWriter, image string, labels map[string]string, namespace, targetName, kind string, useTag, ignoreImageID bool, co []ociremote.Option, cfg valintPkg.Application, l logger.Logger) error {
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
		useTag, ignoreImageID,
		&cfg,
		l,
		co...,
	)

	if err != nil {
		return err
	}

	return nil
}

func runPolicy(w http.ResponseWriter, image string, labels map[string]string, namespace, targetName, kind string, useTag, ignoreImageID bool, co []ociremote.Option, cfg valintPkg.Application, l logger.Logger) {
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
		useTag, ignoreImageID,
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
