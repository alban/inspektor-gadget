HELM ?= helm
HELM_DOCS_IMAGE ?= jnorwood/helm-docs:v1.14.2
BUILD_DIR ?= bin
OUTPUT_DIR ?= $(BUILD_DIR)
CHART_DIR := $(BUILD_DIR)/gadget

# This version will be overridden by the release process to match the tag
CHART_VERSION ?= "1.0.0-dev"
APP_VERSION ?= $(shell ./../tools/image-tag branch)
SED_VERSION := $(shell sed --version 2>&1)

.DEFAULT_GOAL := help

clean:
	rm -rf $(BUILD_DIR)

build: clean
	@echo "Building chart:"
	mkdir -p $(BUILD_DIR)
	cp -r gadget $(BUILD_DIR)
	mv $(CHART_DIR)/Chart.yaml.tmpl $(CHART_DIR)/Chart.yaml
ifeq ($(findstring GNU,$(SED_VERSION)),GNU)
	@echo "Using GNU sed"
	sed -i "s/%VERSION%/$(CHART_VERSION)/g" $(CHART_DIR)/Chart.yaml
	sed -i "s/%APP_VERSION%/$(APP_VERSION)/g" $(CHART_DIR)/Chart.yaml
else
	@echo "Using BSD sed"
	sed -i "" "s/%VERSION%/$(CHART_VERSION)/g" $(CHART_DIR)/Chart.yaml
	sed -i "" "s/%APP_VERSION%/$(APP_VERSION)/g" $(CHART_DIR)/Chart.yaml
endif
	@echo "Preparing docs"
	docker run --user $(shell id -u):$(shell id -g) -v $(shell pwd)/$(CHART_DIR):/helm-docs $(HELM_DOCS_IMAGE) -s file
	@echo "Charts available at: $(CHART_DIR)"

# install uses 'helm upgrade --install' to make chart installation idempotent.
install: build
	$(HELM) upgrade --install gadget $(CHART_DIR) --namespace gadget --create-namespace

uninstall:
	$(HELM) uninstall gadget --namespace gadget

lint: build
	$(HELM) lint $(CHART_DIR)

template: build
	$(HELM) template gadget $(CHART_DIR) --namespace gadget --skip-crds | tee $(OUTPUT_DIR)/deploy.yaml

package: build
	$(HELM) package $(CHART_DIR) -d $(BUILD_DIR)

help:
	@echo "Usage: make <target>"
	@echo
	@echo "Targets:"
	@echo "  clean     - Clean built chart"
	@echo "  build     - Build chart"
	@echo "  install   - Install chart"
	@echo "  uninstall - Uninstall chart"
	@echo "  lint      - Lint chart"
	@echo "  template  - Template chart"
	@echo "  package   - Package chart"
	@echo "  help      - Print this help"
