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
	"time"

	"github.com/scribe-security/basecli/logger"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"

	"github.com/scribe-security/gatekeeper-valint/internal/config"
	"github.com/scribe-security/gatekeeper-valint/pkg/utils"
	gensbomPkg "github.com/scribe-security/gensbom/pkg"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const (
	apiVersion = "externaldata.gatekeeper.sh/v1beta1"
	tlsCert    = "/valint-certs/tls.crt"
	tlsKey     = "/valint-certs/tls.key"
	timeout    = 30 * time.Second
)

type ProviderCmd struct {
	cfg    *config.Application
	ctx    context.Context
	logger logger.Logger
}

func NewProviderCmd(ctx context.Context, cfg *config.Application) (*ProviderCmd, error) {
	gensbomCfg := cfg.GetGensbomConfig()
	l, err := gensbomPkg.InitCommandLogger("", &gensbomCfg, nil)
	if err != nil {
		return nil, err
	}

	return &ProviderCmd{
		cfg:    cfg,
		ctx:    ctx,
		logger: l,
	}, nil
}

func (cmd *ProviderCmd) Run() error {

	fmt.Println("starting HTTPS server...")

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

	// iterate over all keys
	for _, key := range providerRequest.Request.Keys {
		fmt.Println("valint verify signature for:", key)
		ref, err := name.ParseReference(key)
		if err != nil {
			utils.SendResponse(nil, fmt.Sprintf("ERROR (ParseReference(%q)): %v", key, err), w)
			return
		}

		img, err := remote.Image(ref, remote.WithContext(ctx))
		if err != nil {
			utils.SendResponse(nil, fmt.Sprintf("ERROR (Image(%q)): %v", key, err), w)
			return
		}

		imageID, err := img.ConfigName()
		if err != nil {
			utils.SendResponse(nil, fmt.Sprintf("ERROR (ConfigName(%q)): %v", key, err), w)
			return
		}

		cfg := cmd.cfg.GetGensbomConfig()
		err = gensbomPkg.VerifyAdmissionImage(ref.String(),
			imageID.String(),
			&cfg,
			cmd.logger,
			co...,
		)

		if err != nil {
			utils.SendResponse(nil, fmt.Sprintf("ERROR (VerifyAdmissionImage(%q)): %v", key, err), w)
			return
		}
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
			utils.SendResponse(nil, "operation timed out", w)
		case <-processDone:
		}
	}
}
