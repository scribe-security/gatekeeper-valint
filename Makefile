BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)
NAMESPACE=gatekeeper-valint
NAME=gatekeeper-valint
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
	curl -sSfL https://get.scribesecurity.com/install.sh  | sh -s -- -t valint -D -d -b $(TEMPDIR)

.PHONY: bootstrap-go
bootstrap-go:
	GOPRIVATE=github.com/scribe-security/* go mod download

.PHONY: bootstrap
bootstrap: bootstrap-tools ## Download and install all go dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Bootstrapping dependencies)

.PHONY: install_local_scribe
install_local_scribe:  ## Install admission with scribe
	SCRIBE_CLIENT_ID=$(SCRIBE_CLIENT_ID) SCRIBE_CLIENT_SECRET=$(SCRIBE_CLIENT_SECRET) bash scripts/install_scribe_provider.sh $(NAME) $(NAMESPACE) 

.PHONY: install_local_scribe_x509
install_local_scribe_x509:  ## Install admission with scribe
	SCRIBE_CLIENT_ID=$(SCRIBE_CLIENT_ID) SCRIBE_CLIENT_SECRET=$(SCRIBE_CLIENT_SECRET) bash scripts/install_scribe_provider.sh $(NAME) $(NAMESPACE) x509

.PHONY: install_local_scribe_sigstore
install_local_scribe_sigstore:  ## Install admission with scribe
	SCRIBE_CLIENT_ID=$(SCRIBE_CLIENT_ID) SCRIBE_CLIENT_SECRET=$(SCRIBE_CLIENT_SECRET) bash scripts/install_scribe_provider.sh $(NAME) $(NAMESPACE) sigstore


.PHONY: install_gatekeeper
install_gatekeeper:
	helm install gatekeeper/gatekeeper  \
    --name-template=gatekeeper \
    --namespace gatekeeper-system --create-namespace \
    --set enableExternalData=true \
    --set controllerManager.dnsPolicy=ClusterFirst,audit.dnsPolicy=ClusterFirst \
    --set validatingWebhookTimeoutSeconds=30

.PHONY: install_local_oci
install_local_oci: ## Install admission with oci from local dir
	@if helm status $(NAME) -n $(NAMESPACE) > /dev/null 2>&1; then \
		helm upgrade --debug --reset-values --force \
			--set certs.caBundle=$(cat certs/ca.crt | base64 | tr -d '\n') \
			--set certs.tlsCrt="$(cat certs/tls.crt)" \
			--set certs.tlsKey="$(cat certs/tls.key)" \
			$(NAME) -n $(NAMESPACE) ./charts/gatekeeper-valint --devel; \
	else \
		helm install --debug  \
			--set certs.caBundle=$(cat certs/ca.crt | base64 | tr -d '\n') \
			--set certs.tlsCrt="$(cat certs/tls.crt)" \
			--set certs.tlsKey="$(cat certs/tls.key)" \
			$(NAME) -n $(NAMESPACE) ./charts/gatekeeper-valint --devel; \
	fi

.PHONY: uninstall
uninstall:
	@helm uninstall $(NAME) -n $(NAMESPACE)

.PHONY: build
build: $(SNAPSHOTDIR) ## Build release snapshot binaries and packages

$(SNAPSHOTDIR): ## Build snapshot release binaries and packages
	$(call title,Building snapshot artifacts)
	@DIR=$(SNAPSHOTDIR) make mod-goreleaser
	# build release snapshots
	BUILD=true BUILD_GIT_TREE_STATE=$(GITTREESTATE) $(TEMPDIR)/latest/goreleaser release --debug ${BUILD:+--skip-publish2} --snapshot --skip-sign --clean --skip-validate --config $(TEMPDIR)/goreleaser.yml

.PHONY: binary
binary: ## Build snapshot binaries only
	$(call title,Building snapshot artifacts)
	#@DIR=$(SNAPSHOTDIR) make mod-goreleaser
	# build release snapshots
	# $(TEMPDIR)/latest/goreleaser build --clean --snapshot --config $(TEMPDIR)/goreleaser.yaml
	$(call title,Building snapshot artifacts)
	@DIR=$(SNAPSHOTDIR) make mod-goreleaser
	# build release snapshots
	BUILD=true BUILD_GIT_TREE_STATE=$(GITTREESTATE) $(TEMPDIR)/latest/goreleaser build --single-target --debug --snapshot --clean --config $(TEMPDIR)/goreleaser.yml


.PHONY: release
release: clean-dist ## goreleaser release and push packages.
	$(call title,Building snapshot artifacts)
	# create a config with the dist dir overridden
	@DIR=$(DISTDIR) make mod-goreleaser
	# build release snapshots
	BUILD_GIT_TREE_STATE=$(GITTREESTATE) \
	VERSION=$(VERSION:v%=%) \
	$(TEMPDIR)/latest/goreleaser release --debug  --skip-sign --clean --config $(TEMPDIR)/goreleaser.yml

.PHONY: dev-release
dev-release: clean-dist ## goreleaser dev-release and push packages.
	IsDev=true make release


.PHONY: mod-goreleaser 
mod-goreleaser:
	# create a config with the dist dir overridden
	echo "dist: $(DIR)" > $(TEMPDIR)/goreleaser.yml
	cat .goreleaser.yml >> $(TEMPDIR)/goreleaser.yml

.PHONY: test
test:
	go test -count=1 -test.v ./...

.PHONY: clean
clean: clean-dist clean-snapshot ## Remove previous builds, result reports, and test cache

.PHONY: clean-snapshot
clean-snapshot:
	rm -rf $(SNAPSHOTDIR) $(TEMPDIR)/goreleaser.yaml

.PHONY: clean-dist
clean-dist:
	rm -rf $(DISTDIR) $(TEMPDIR)/goreleaser.yaml

.PHONY: clean-test
clean-test:
	@helm -ngatekeeper-system delete gatekeeper || true
	@helm -ngatekeeper-valint delete gatekeeper-valint || true

.PHONY: clean-provider
clean-provider:
	@helm -ngatekeeper-valint delete gatekeeper-valint || true

.PHONY: upstream-valint
upstream-valint:
	GOPRIVATE=github.com/scribe-security/* go get github.com/scribe-security/valint@main

.PHONY: minikube_start
minikube_start: ## Install admission on minikube
	@minikube start  --container-runtime=docker --cpus 2 --memory 2gb --disk-size=5g --kubernetes-version=1.24.0

.PHONY: minikube_dashboard
minikube_dashboard: ## Minikube dashboard
	@minikube dashboard

.PHONY: logs
logs: ## Read admission logs
	@kubectl logs --all-containers=true --tail=-1 -l gatekeeper-valint -n  $(NAMESPACE)  | grep '^{' | jq -C -r '.' | sed 's/\\n/\n/g; s/\\t/\t/g'

.PHONY: clean_namespace
clean_namespace: clean ## Delete admission namespace
	@kubectl delete namespace $(NAMESPACE)  || true


.PHONY: accept_test
accept_test: ## Accept test 
	kubectl delete -f policy/examples/valid.yaml || true
	kubectl apply -f policy/examples/valid.yaml
