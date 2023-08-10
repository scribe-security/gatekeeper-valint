BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)
NAMESPACE=gatekeeper-valint-provider
NAME=gatekeeper-valint-provider
ADMISSION_PRE_RELASE=$(ADMISSION_IMAGE):dev-latest-gk-provider
## Build variables
TEMPDIR = ./.tmp
DISTDIR=./dist
SNAPSHOTDIR=./snapshot

ifeq "$(strip $(VERSION))" ""
 override VERSION = $(shell git describe --always --tags --dirty)
endif

# used to generate the changelog from the second to last tag to the current tag (used in the release pipeline when the release tag is in place)
LAST_TAG := $(shell git describe --always --abbrev=0 --tags $(shell git rev-list --tags --max-count=1))
SECOND_TO_LAST_TAG := $(shell git describe --always --abbrev=0 --tags $(shell git rev-list --tags --skip=1 --max-count=1))

## Variable assertions

ifndef TEMPDIR
	$(error TEMPDIR is not set)
endif

ifndef DISTDIR
	$(error DISTDIR is not set)
endif

ifndef SNAPSHOTDIR
	$(error SNAPSHOTDIR is not set)
endif

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef


include env

## Tasks
.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'

$(TEMPDIR):
	mkdir -p $(TEMPDIR)

.PHONY: bootstrap-tools 
bootstrap-tools: $(TEMPDIR)
	# curl -sfL https://install.goreleaser.com/github.com/goreleaser/goreleaser.sh | sh -s -- -b $(TEMPDIR)/latest
	mkdir -p ./$(TEMPDIR)/latest
	GOBIN=$(shell realpath $(TEMPDIR)/latest) go install github.com/goreleaser/goreleaser@v1.18.2

.PHONY: bootstrap-go
bootstrap-go:
	GOPRIVATE=github.com/scribe-security/* go mod download

.PHONY: bootstrap
bootstrap: bootstrap-tools ## Download and install all go dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Bootstrapping dependencies)


.PHONY: install_namespace
install_namespace:  ## Install Namespace
	@kubectl create namespace $(NAMESPACE)
	
.PHONY: install_local_scribe
install_local_scribe:  ## Install admission with scribe
	@if helm status $(NAME) -n $(NAMESPACE) > /dev/null 2>&1; then \
		helm upgrade --debug --reset-values --force \
			--set scribe.service.enable=true \
			--set scribe.auth.client_id=$(SCRIBE_CLIENT_ID) \
			--set scribe.auth.client_secret=$(SCRIBE_CLIENT_SECRET) \
			$(NAME) -n $(NAMESPACE) ./manifest --devel; \
	else \
		helm install --debug  \
			--set scribe.service.enable=true \
			--set scribe.auth.client_id=$(SCRIBE_CLIENT_ID) \
			--set scribe.auth.client_secret=$(SCRIBE_CLIENT_SECRET) \
			$(NAME) -n $(NAMESPACE) ./manifest --devel; \
	fi

.PHONY: install_local_oci
install_local_oci: ## Install admission with oci from local dir
		@kubectl apply -f manifest
		@kubectl apply -f policy/template.yaml
		@kubectl apply -f policy/constraint.yaml

.PHONY: install_local
clean-local: ## Clean admission from local dir
		@kubectl delete -f manifest
		@kubectl delete -f policy

.PHONY: uninstall
uninstall:
	@helm uninstall gatekeeper-valint-provider -n gatekeeper-valint-provider 



.PHONY: build
build: $(SNAPSHOTDIR) ## Build release snapshot binaries and packages

$(SNAPSHOTDIR): ## Build snapshot release binaries and packages
	$(call title,Building snapshot artifacts)
	@DIR=$(SNAPSHOTDIR) make mod-goreleaser
	# build release snapshots
	BUILD=true BUILD_GIT_TREE_STATE=$(GITTREESTATE) $(TEMPDIR)/latest/goreleaser release --debug ${BUILD:+--skip-publish2} --snapshot --skip-sign --clean --skip-validate --config $(TEMPDIR)/goreleaser.yml

.PHONY: mod-goreleaser 
mod-goreleaser:
	# create a config with the dist dir overridden
	echo "dist: $(DIR)" > $(TEMPDIR)/goreleaser.yml
	cat .goreleaser.yml >> $(TEMPDIR)/goreleaser.yml

.PHONY: clean
clean: clean-dist clean-snapshot ## Remove previous builds, result reports, and test cache

.PHONY: clean-snapshot
clean-snapshot:
	rm -rf $(SNAPSHOTDIR) $(TEMPDIR)/goreleaser.yaml

.PHONY: clean-dist
clean-dist:
	rm -rf $(DISTDIR) $(TEMPDIR)/goreleaser.yaml

.PHONY: upstream-gensbom
upstream-gensbom:
	GOPRIVATE=github.com/scribe-security/* go get github.com/scribe-security/gensbom@master

.PHONY: clean-namespace
clean-namespace: ## Delete admission namespace
	@kubectl delete namespace $(NAMESPACE)  || true


# .PHONY: login
# login: ## Add Image Registry secret
# 	kubectl create secret docker-registry $(REPO_SECRET_NAME) \
# 		--docker-server=$(REPO_URL) \
# 		--docker-username=$(REPO_USERNAME) \
# 		--docker-password=$(REPO_PASSWORD) \
# 		-n $(NAMESPACE) || true

# .PHONY: namespace
# install_namespace:  ## Install Namespace
# 	@kubectl create namespace $(NAMESPACE)

# .PHONY: install
# install: ## Install admission (release helm)
# 	@helm install --devel --debug  \
# 		--set scribe.auth.client_id=$(SCRIBE_CLIENT_ID) \
# 		--set scribe.auth.client_secret=$(SCRIBE_CLIENT_SECRET) \
# 		$(NAME) -n $(NAMESPACE) scribe/$(NAME)  --devel

# .PHONY: install_local_scribe
# install_local_scribe:  ## Install admission with scribe
# 	@if helm status $(NAME) -n $(NAMESPACE) > /dev/null 2>&1; then \
# 		helm upgrade --debug --reset-values --force \
# 			--set scribe.service.enable=true \
# 			--set scribe.auth.client_id=$(SCRIBE_CLIENT_ID) \
# 			--set scribe.auth.client_secret=$(SCRIBE_CLIENT_SECRET) \
# 			$(NAME) -n $(NAMESPACE) ./charts/$(NAME) --devel; \
# 	else \
# 		helm install --debug  \
# 			--set scribe.service.enable=true \
# 			--set scribe.auth.client_id=$(SCRIBE_CLIENT_ID) \
# 			--set scribe.auth.client_secret=$(SCRIBE_CLIENT_SECRET) \
# 			$(NAME) -n $(NAMESPACE) ./charts/$(NAME) --devel; \
# 	fi
# 	@make upgrade_local_glob

# .PHONY: install_local_oci
# install_local_oci: login ## Install admission with oci
# 	@if helm status $(NAME) -n $(NAMESPACE) > /dev/null 2>&1; then \
# 		helm upgrade --debug --reset-values --force \
# 			--set config.attest.cocosign.storer.OCI.enable=true \
# 			--set config.attest.cocosign.storer.OCI.repo=${REPO_FULL} \
# 			--set imagePullSecrets={$(REPO_SECRET_NAME)} \
# 			$(NAME) -n $(NAMESPACE) ./charts/$(NAME) --devel; \
# 	else \
# 		helm install --debug \
# 			--set config.attest.cocosign.storer.OCI.enable=true \
# 			--set config.attest.cocosign.storer.OCI.repo=${REPO_FULL} \
# 			--set imagePullSecrets={$(REPO_SECRET_NAME)} \
# 			$(NAME) -n $(NAMESPACE) ./charts/$(NAME) --devel; \
# 	fi
# 	@make upgrade_local_glob

# .PHONY: upgrade_local_glob
# upgrade_local_glob:
# 	@helm upgrade --debug --reuse-values \
# 		--set config.admission.glob={\.\*nginx\.\*} \
# 		$(NAME) -n $(NAMESPACE) ./charts/$(NAME) --devel 

# .PHONY: upgrade_local_format
# upgrade_local_format:
# 	@helm upgrade --debug --reuse-values \
# 		--set config.verify.input-format=statement \
# 		$(NAME) -n $(NAMESPACE) ./charts/$(NAME) --devel

# .PHONY: show_values
# show_values:
# 	@helm get values --debug $(NAME) -n $(NAMESPACE)

# .PHONY: bootstrap
# bootstrap:
# 	@helm plugin install https://github.com/karuppiah7890/helm-schema-gen.git
# 	@GO111MODULE=on go get github.com/norwoodj/helm-docs/cmd/helm-docs

# .PHONY: gen_schema
# gen_docs:
# 	@helm schema-gen charts/$(NAME)/values.yaml > charts/$(NAME)/values.schema.json 
# 	@helm-docs -g charts/gatekeeper-valint-provider -t charts/gatekeeper-valint-provider/README.md.gotmp

.PHONY: minikube_start
minikube_start: ## Install admission on minikube
	@minikube start  --container-runtime=docker --cpus 2 --memory 2gb --disk-size=5g --kubernetes-version=1.24.0

# .PHONY: minikube_load
# minikube_load: ## Load admission to minikube
# 	@minikube image load scribesecuriy.jfrog.io/scribe-docker-public-local/valint:latest

# .PHONY: minikube_docker
# minikube_docker: ## Map local daemon to minikube
# 	$(eval $(shell minikube -p minikube docker-env 1>&2))

# .PHONY: minikube_install_local
# minikube_install_local: clean install_local ## Install admission on minikube (Local helm)

# .PHONY: minikube_install
# minikube_install: clean install ## Install admission on minikube (release helm)

.PHONY: minikube_dashboard
minikube_dashboard: ## Minikube dashboard
	@minikube dashboard

.PHONY: logs
logs: ## Read admission logs
	@kubectl logs --all-containers=true --tail=-1 -l gatekeeper-valint-provider -n  $(NAMESPACE)  | grep '^{' | jq -C -r '.' | sed 's/\\n/\n/g; s/\\t/\t/g'

.PHONY: clean_namespace
clean_namespace: clean ## Delete admission namespace
	@kubectl delete namespace $(NAMESPACE)  || true

.PHONY: cosign_sign
cosign_sign:
	../valint/.tmp/latest/cosign sign scribesecuriy.jfrog.io/scribe-docker-public-local/test/gensbom_alpine_input:latest

# .PHONY: clean
# clean: ## Uninstall admission
# 	@helm uninstall $(NAME) --debug -n $(NAMESPACE) || true
# 	$(shell kubectl --namespace $(NAMESPACE) delete "$$(kubectl api-resources --namespaced=true --verbs=delete -o name | tr '\n' ',' | sed -e 's/,$$//')" --all)  || true

.PHONY: accept_test
accept_test: ## Accept test 
	kubectl delete -f policy/examples/valid.yaml
	kubectl apply -f policy/examples/valid.yaml

# .PHONY: deny_test
# deny_test: ## Deny test
# 	@kubectl create namespace test || true
# 	@kubectl label namespace test admission.scribe.dev/include=true
# 	@kubectl apply -f charts/gatekeeper-valint-provider/examples/deny_deployment.yaml -n test

# .PHONY: upload_oci_nginx
# upload_oci_nginx: ## Upload Accepted image to OCI storer
# 	valint bom nginx:1.14.2 -f --oci --oci-repo scribesecuriy.jfrog.io/scribe-docker-local/attestation -o statement

# .PHONY: upload_scribe_nginx
# upload_scribe_nginx: ## Upload Accepted Attest, image to Scribe storer
# 	valint bom nginx:1.14.2 -f -E -o attest --scribe.client-id $(SCRIBE_CLIENT_ID) --scribe.client-secret $(SCRIBE_CLIENT_SECRET)  

# ##--scribe.url $(SCRIBE_URL) --scribe.login-url $(SCRIBE_LOGIN_URL) --scribe.auth.audience $(SCRIBE_AUDIENCE)

# .PHONY: clean_test
# clean_test: ## Clean test admission
# 	@kubectl delete -f charts/gatekeeper-valint-provider/examples/accept_deployment.yaml -n test || true
# 	# @kubectl delete -f charts/gatekeeper-valint-provider/examples/deny_deployment.yaml -n test || true


# .PHONY: sync_pre_release
# sync_pre_release:
# 	$(shell bash ./scripts/sync_pre_relase.sh $(ADMISSION_PRE_RELASE)) || true


# list_vesrsions:
# 	helm search repo scribe/gatekeeper-valint-provider --devel --versions


## DEMO
## 1) Prepare cluster
## make install_minikube
## Or other cluster.

## 2) Install Namespace for scribe admission (Once per cluster)
## make install_namespace.

## 3) Install scribe admission using Scribe Store.
## make install_local_scribe
## Verify values using `make show_values`

## OR OCI `make install_local_oci`

## 4) Upload Nginx to Scribe.
## make upload_scribe_nginx
## OR OCI `make upload_oci_nginx`

## 5) Show Deny and Accept tests.
## make deny_test
## make accept_test

### To clean admission for reinstall a new version please run `make clean`