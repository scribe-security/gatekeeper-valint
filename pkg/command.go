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

	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"

	"github.com/scribe-security/gatekeeper-valint/internal/config"
	"github.com/scribe-security/gatekeeper-valint/pkg/utils"
	valintPkg "github.com/scribe-security/valint/pkg"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
)

const (
	apiVersion       = "externaldata.gatekeeper.sh/v1beta1"
	tlsCert          = "/valint-certs/tls.crt"
	tlsKey           = "/valint-certs/tls.key"
	defaultTimeout   = 300 * time.Second
	overhead         = 2 * time.Second
	requestKeyPrefix = "request:"
	objectKeyPrefix  = "object:"
	reviewKeyPrefix  = "review:"
)

type Metadata struct {
	Labels    map[string]string `yaml:"labels,omitempty" json:"labels,omitempty" mapstructure:"labels"`
	Namespace string            `yaml:"namespace,omitempty" json:"namespace,omitempty" mapstructure:"namespace"`
	Name      string            `yaml:"name,omitempty" json:"name,omitempty" mapstructure:"name"`
}

type AdmissionReviewObject struct {
	Kind     string   `yaml:"kind,omitempty" json:"kind,omitempty" mapstructure:"kind"`
	Metadata Metadata `yaml:"metadata,omitempty" json:"metadata,omitempty" mapstructure:"metadata"`
}

type AdmissionReview struct {
	Object    AdmissionReviewObject `yaml:"object,omitempty" json:"object,omitempty" mapstructure:"object"`
	Operation string                `yaml:"operation,omitempty" json:"operation,omitempty" mapstructure:"operation"`
}

type ProviderCmd struct {
	cfg          *config.Application
	ctx          context.Context
	logger       logger.Logger
	policySelect *valintPkg.PolicySelectStruct
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

	var policySelect *valintPkg.PolicySelectStruct
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
		ReadTimeout:       100 * time.Second,
		WriteTimeout:      cmd.timeout,
		ReadHeaderTimeout: 100 * time.Second,
	}

	if err := srv.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
		return err
	}

	return nil
}

func ReadPolicySelectStruct(file string) (*valintPkg.PolicySelectStruct, error) {
	var policySelect valintPkg.PolicySelectStruct
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

func (cmd *ProviderCmd) decodeKeys(providerReq externaldata.ProviderRequest) ([]string, map[string]string, string, string, string, string, error) {
	var images []string
	var labels map[string]string
	var namespace, name, kind, operation string
	var admissionRequest AdmissionReview
	for _, key := range providerReq.Request.Keys {
		if strings.HasPrefix(key, reviewKeyPrefix) {
			base := strings.TrimPrefix(key, reviewKeyPrefix)
			data, err := base64.StdEncoding.DecodeString(base)
			if err == nil {
				err := json.Unmarshal(data, &admissionRequest)
				if err == nil {
					object := admissionRequest.Object
					labels = object.Metadata.Labels
					name = object.Metadata.Name
					namespace = object.Metadata.Namespace
					kind = object.Kind
					operation = admissionRequest.Operation
				}
			}
		} else {
			images = append(images, key)
		}
	}

	return images, labels, namespace, name, kind, operation, nil
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
	images, labels, namespace, name, kind, operation, err := cmd.decodeKeys(providerRequest)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("unable to decode provider keys: %v", err), w)
		return
	}
	cmd.logger.Infof("evaluating (%d) '%s', Labels: %s, Namespace: %s, Name: %s, Kind: %s, Operation: %s", len(images), images, labels, namespace, name, kind, operation)
	if operation != "CREATE" {
		cmd.logger.Info("Skipping API Call, only operation CREATE is supported")
		emptyResults := make([]externaldata.Item, 0)
		utils.SendResponse(&emptyResults, "", w)
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
		for _, image := range images {
			err := valintPkg.RunPolicy(image, labels, namespace, name, kind, useTag, ignoreImageID, co, cmd.cfg.Valint, cmd.logger)
			if err != nil {
				utils.SendResponse(nil, fmt.Sprintf("ERROR: %v", err), w)
			}
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

			errs := valintPkg.RunPolicySelectWithError(w, image, labels, namespace, name, kind, useTag, ignoreImageID, co, cmd.policySelect.Apply, cmd.policySelect.Warning, cmd.cfg.Valint, cmd.logger)
			if len(errs) > 0 {
				policyErrs = append(policyErrs, errs...)
				policyErrMsg := []string{}
				for _, e := range errs {
					cmd.logger.Warnf("Scribe Admission refused '%s' deployment to '%s' namespace.%s", image, namespace, e)
					policyErrMsg = append(policyErrMsg, fmt.Sprintf("\n- %s", e))
				}
				errMsg = errMsg + fmt.Sprintf("\nScribe Admission refused '%s' deployment to '%s'.\n%s", image, namespace, strings.Join(policyErrMsg, ""))
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
			utils.SendResponse(nil, "ERROR: operation timed out", w)
		case <-processDone:
		}
	}
}
