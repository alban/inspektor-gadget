TAG := `git describe --tags --always`
VERSION :=

CONTAINER_REPO ?= docker.io/kinvolk/gadget
IMAGE_TAG ?= $(shell ./tools/image-tag branch)

MINIKUBE ?= minikube

# Adds a '-dirty' suffix to version string if there are uncommitted changes
changes := $(shell git status --porcelain)
ifeq ($(changes),)
	VERSION := $(TAG)
else
	VERSION := $(TAG)-dirty
endif

include crd.mk
include tests.mk

LDFLAGS := "-X main.version=$(VERSION) \
-X main.gadgetimage=$(CONTAINER_REPO):$(IMAGE_TAG) \
-extldflags '-static'"

.DEFAULT_GOAL := build
.PHONY: build
build: manifests generate local-gadget kubectl-gadget gadget-container

# local-gadget
.PHONY: local-gadget
local-gadget:
	make -C gadget-container ebpf-objects
	go build \
		-tags withebpf \
		-ldflags "-X main.version=$(VERSION)" \
		-o local-gadget \
		github.com/kinvolk/inspektor-gadget/cmd/local-gadget

# kubectl-gadget
.PHONY: kubectl-gadget
kubectl-gadget: kubectl-gadget-linux-amd64 kubectl-gadget-darwin-amd64 kubectl-gadget-windows-amd64

.PHONY: kubectl-gadget-linux-amd64
kubectl-gadget-linux-amd64:
	GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-ldflags $(LDFLAGS) \
		-o kubectl-gadget-linux-amd64 \
		github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget

.PHONY: kubectl-gadget-darwin-amd64
kubectl-gadget-darwin-amd64:
	GO111MODULE=on CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build \
		-ldflags $(LDFLAGS) \
		-o kubectl-gadget-darwin-amd64 \
		github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget

.PHONY: kubectl-gadget-windows-amd64
kubectl-gadget-windows-amd64:
	GO111MODULE=on CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build \
		-ldflags $(LDFLAGS) \
		-o kubectl-gadget-windows-amd64 \
		github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget

.PHONY: install-user-linux
install-user-linux: kubectl-gadget-linux-amd64
	mkdir -p ~/.local/bin/
	cp kubectl-gadget-linux-amd64 ~/.local/bin/kubectl-gadget

# gadget container
.PHONY: gadget-container
gadget-container:
	docker build -t $(CONTAINER_REPO):$(IMAGE_TAG) -f gadget.Dockerfile .

.PHONY: push-gadget-container
push-gadget-container:
	docker push $(CONTAINER_REPO):$(IMAGE_TAG)

# tests
.PHONY: test
test:
	go test -test.v ./...

.PHONY: controller-tests
controller-tests: kube-apiserver etcd kubectl
	ACK_GINKGO_DEPRECATIONS=1.16.4 \
	TEST_ASSET_KUBE_APISERVER=$(KUBE_APISERVER_BIN) \
	TEST_ASSET_ETCD=$(ETCD_BIN) \
	TEST_ASSET_KUBECTL=$(KUBECTL_BIN) \
	go test -test.v ./pkg/controllers/... -controller-test

.PHONY: local-gadget-tests
local-gadget-tests:
	make -C gadget-container ebpf-objects
	# Compile and execute in separate commands because Go might not be
	# available in the root environment
	go test -c ./pkg/local-gadget-manager \
		-tags withebpf
	sudo ./local-gadget-manager.test -test.v -root-test
	rm -f ./local-gadget-manager.test

.PHONY: integration-tests
integration-tests:
	KUBECTL_GADGET="$(shell pwd)/kubectl-gadget-linux-amd64" \
		go test ./integration/... \
			-integration \
			-image $(CONTAINER_REPO):$(IMAGE_TAG)

# minikube
LIVENESS_PROBE_INITIAL_DELAY_SECONDS ?= 10
.PHONY: minikube-install
minikube-install: gadget-container
	# Unfortunately, minikube-cache and minikube-image have bugs in older
	# versions. And new versions of minikube don't support all eBPF
	# features. So we have to keep "docker-save|docker-load" for now.
	docker save $(CONTAINER_REPO):$(IMAGE_TAG) | pv | (eval $(shell $(MINIKUBE) -p minikube docker-env | grep =) && docker load)
	# Delete traces CRD first: the gadget DaemonSet needs to be running
	# because of Finalizers.
	kubectl delete crd traces.gadget.kinvolk.io || true
	./kubectl-gadget-linux-amd64 deploy | kubectl delete -f - || true
	./kubectl-gadget-linux-amd64 deploy --traceloop=false --hook-mode=fanotify | \
		sed 's/imagePullPolicy: Always/imagePullPolicy: Never/g' | \
		sed 's/initialDelaySeconds: 10/initialDelaySeconds: '$(LIVENESS_PROBE_INITIAL_DELAY_SECONDS)'/g' | \
		kubectl apply -f -
