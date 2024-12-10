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
	"sync"
	"time"

	"github.com/scribe-security/basecli/logger"
	"gopkg.in/yaml.v2"
	"k8s.io/klog/v2"

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
	inputKeyPrefix   = "input:"
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

	// mux := http.NewServeMux()
	// mux.HandleFunc("/validate", processTimeout(cmd.Validate, timeoutWithOverhead))

	// srv := &http.Server{
	// 	Addr: fmt.Sprintf(":%d", cmd.cfg.Provider.Port),
	// 	// WriteTimeout:      cmd.timeout,
	// 	Handler:           mux,
	// 	ReadHeaderTimeout: 5 * time.Second,
	// }

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
		if strings.HasPrefix(key, inputKeyPrefix) {
			base := strings.TrimPrefix(key, inputKeyPrefix)
			data, err := base64.StdEncoding.DecodeString(base)
			if err == nil {
				m := make(map[string]interface{})
				json.Unmarshal(data, &m)
				v, _ := json.MarshalIndent(m, "", "  ")
				cmd.logger.Debugf("Constraint input: %s", string(v))
			}
		} else if strings.HasPrefix(key, reviewKeyPrefix) {
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
					if operation != "" {
						v, _ := json.MarshalIndent(admissionRequest, "", "  ")
						cmd.logger.Debugf("Admission request: %s", string(v))
					}

				}
			}
		} else {
			images = append(images, key)
		}
	}

	return images, labels, namespace, name, kind, operation, nil
}

func (cmd *ProviderCmd) Validate(w http.ResponseWriter, req *http.Request) {
	// cmd.logger.Info("validating request")

	// only accept POST requests
	if req.Method != http.MethodPost {
		utils.SendResponse(nil, "only POST is allowed", http.StatusOK, false, w)
		return
	}

	// read request body
	requestBody, err := io.ReadAll(req.Body)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("unable to read request body: %v", err), http.StatusOK, false, w)
		return
	}

	// parse request body
	var providerRequest externaldata.ProviderRequest
	err = json.Unmarshal(requestBody, &providerRequest)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), http.StatusOK, false, w)
		return
	}
	useTag := cmd.policySelect.UseTag
	ignoreImageID := cmd.policySelect.IgnoreImageID
	targetFallbackRepoDigest := cmd.policySelect.TargetFallbackRepoDigest
	images, labels, namespace, name, kind, operation, err := cmd.decodeKeys(providerRequest)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("unable to decode provider keys: %v", err), http.StatusOK, false, w)
		return
	}

	if len(images) == 0 {
		cmd.logger.Debugf("Skipping API Call, no images found in resource, Labels: %s, Namespace: %s, Name: %s, Kind: %s, Operation: %s", labels, namespace, name, kind, operation)
		emptyResults := make([]externaldata.Item, 0)
		utils.SendResponse(&emptyResults, "", http.StatusOK, false, w)
		return
	}

	onlyCreate, found := os.LookupEnv("ONLY_CREATE")
	if found && strings.ToLower(onlyCreate) == "true" && operation != "CREATE" {
		cmd.logger.Debugf("Skipping API Call, only operation CREATE is supported, Images (%d): %s, Labels: %s, Namespace: %s, Name: %s, Kind: %s, Operation: %s", len(images), images, labels, namespace, name, kind, operation)
		emptyResults := make([]externaldata.Item, 0)
		utils.SendResponse(&emptyResults, "", http.StatusOK, false, w)
		return
	}

	if operation != "CREATE" && operation != "UPDATE" {
		cmd.logger.Debug("Skipping API Call, only operation CREATE is supported, Images (%d): %s, Labels: %s, Namespace: %s, Name: %s, Kind: %s, Operation: %s", len(images), images, labels, namespace, name, kind, operation)
		emptyResults := make([]externaldata.Item, 0)
		utils.SendResponse(&emptyResults, "", http.StatusOK, false, w)
		return
	}

	cmd.logger.Infof("evaluating (%d) '%s', Labels: %s, Namespace: %s, Name: %s, Kind: %s, Operation: %s", len(images), images, labels, namespace, name, kind, operation)

	if cmd.policySelect.Warning {
		cmd.logger.Infof("warning policy is enabled return response")
		emptyResults := make([]externaldata.Item, 0)
		utils.SendResponse(&emptyResults, "", http.StatusOK, false, w)
	}

	results := make([]externaldata.Item, 0)

	ctx, cancel := context.WithTimeout(req.Context(), cmd.timeout)
	defer cancel()

	ro := options.RegistryOptions{}
	co, err := ro.ClientOpts(ctx)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("ERROR: %v", err), http.StatusOK, false, w)
		return
	}
	os.Setenv("PULL_BUNDLE", "true")
	os.Setenv("CONCURRENT_UPLOAD", "true")
	// os.Setenv("GATEKEEPER_VALINT_SCRIBE_RETRY_EXP", "true")
	SetGlobalIsWarning(cmd.policySelect.Warning)

	if cmd.policySelect == nil ||
		(cmd.policySelect != nil && len(cmd.policySelect.Apply) == 0) {
		// Run Default policy
		var policyErrs, errs []error
		var errMsg string
		var wg sync.WaitGroup
		var mu sync.Mutex
		// Run Policy Concurrently

		for _, image := range images {
			wg.Add(1)
			go func(image string) {
				defer wg.Done()
				cmd.logger.Infof("Starting admission thread for '%s'", image)
				err := valintPkg.RunPolicy(image, labels, namespace, name, kind, useTag, ignoreImageID, targetFallbackRepoDigest, co, cmd.cfg.Valint, cmd.logger)
				if err != nil {
					mu.Lock()
					policyErrs = append(policyErrs, errs...)
					policyErrMsg := []string{}
					for _, e := range errs {
						cmd.logger.Warnf("Scribe Admission refused '%s' deployment to '%s' namespace.%s", image, namespace, e)
						policyErrMsg = append(policyErrMsg, fmt.Sprintf("\n- %s", e))
					}
					errMsg = errMsg + fmt.Sprintf("\nScribe Admission refused '%s' deployment to '%s'.\n%s", image, namespace, strings.Join(policyErrMsg, ""))
					mu.Unlock()
				}
			}(image)
		}

		wg.Wait()

		if len(policyErrs) > 0 {
			utils.SendResponseWithWarning(nil, errMsg, http.StatusOK, false, w, cmd.policySelect.Warning)
			return
		}

	} else if cmd.policySelect != nil {
		if cmd.policySelect.GateType != "" && cmd.cfg.Valint.Context.GateTypeField == "" {
			cmd.cfg.Valint.Context.GateTypeField = cmd.policySelect.GateType
		}

		if cmd.cfg.Valint.Context.GateTypeField != "" {
			cmd.logger.Infof("evaluating '%s' on gate '%s'", images, cmd.cfg.Valint.Context.GateTypeField)
		}

		var policyErrs []error
		var errMsg string
		var wg sync.WaitGroup
		var mu sync.Mutex

		_, bundleDir, err := valintPkg.BundleClone(&cmd.cfg.Valint.Attest)
		if err == nil {
			cmd.cfg.Valint.Attest.BundlePath = bundleDir
			cmd.logger.Infof("Admission Setting bundle path to %s", bundleDir)
		} else {
			cmd.logger.Infof("Admission bundle error %s", err)
		}
		for _, image := range images {
			wg.Add(1)
			go func(image string) {
				cmd.logger.Debugf("Image admission thread %s", image)
				errs := valintPkg.RunPolicySelectWithError(w, image, labels, namespace, name, kind, useTag, ignoreImageID, targetFallbackRepoDigest, co, cmd.policySelect.Apply, cmd.policySelect.Warning, cmd.cfg.Valint, cmd.logger)
				if len(errs) > 0 {
					mu.Lock()
					policyErrs = append(policyErrs, errs...)
					policyErrMsg := []string{}
					for _, e := range errs {
						cmd.logger.Warnf("Scribe Admission refused '%s' deployment to '%s' namespace.%s", image, namespace, e)
						policyErrMsg = append(policyErrMsg, fmt.Sprintf("\n- %s", e))
					}
					errMsg = errMsg + fmt.Sprintf("\nScribe Admission refused '%s' deployment to '%s'.\n%s", image, namespace, strings.Join(policyErrMsg, ""))
					mu.Unlock()
				}
				wg.Done()
			}(image)
		}

		wg.Wait()

		if len(policyErrs) > 0 {
			utils.SendResponseWithWarning(nil, errMsg, http.StatusOK, false, w, cmd.policySelect.Warning)
			return
		}

	} else {
		cmd.logger.Warnf("no policy run on request")
	}

	utils.SendResponseWithWarning(&results, "", http.StatusOK, false, w, cmd.policySelect.Warning)
}

type ContextHandler func(w http.ResponseWriter, r *http.Request) error

var GlobalIsWarning bool

func SetGlobalIsWarning(isWarning bool) {
	GlobalIsWarning = isWarning
}

func processTimeout(h http.HandlerFunc, duration time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), duration)
		defer cancel()
		r = r.WithContext(ctx)

		processDone := make(chan bool)
		var err error
		go func() {
			h(w, r)
			processDone <- true
		}()

		select {
		case <-ctx.Done():
			klog.Infof("operation timed out after duration %v", duration)
			err = fmt.Errorf("operation timed out after duration %v", duration)
		case <-processDone:
		}

		if err != nil {
			klog.Warningf("Operation error: %v", err)
			// Maybe this should be http.StatusOK ?
			utils.SendResponseWithWarning(nil, err.Error(), http.StatusInternalServerError, false, w, GlobalIsWarning)
		}
	}
}
