// Copyright 2023 The Inspektor Gadget authors
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

package oci

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
)

const ArtifactHubPkgTemplate = `# Artifact Hub package metadata file
# This file has the automatically generated from gadget.yaml
version: 0.1.0
name: "{{ .Name }}"
category: monitoring-logging
displayName: "{{ .Name }}"
createdAt: "2000-01-01T08:00:00+01:00"
description: "{{ .Description }}"
logoURL: ""
license: ""
homeURL: "{{ .HomepageURL }}"
containersImages:
    - name: gadget
      image: "{{ image }}"
      platforms:
        - linux/amd64
        - linux/arm64
keywords:
    - gadget
links:
    - name: source
      url: "{{ .SourceURL }}"
install: |
    # Run
    ` + "```" + `bash
    sudo ig run {{ image }}
    ` + "```" + `
#changes:
#    - kind: added
#      description: Initial release
provider:
    name: Inspektor Gadget
`

func createOrUpdateArtifactHubPkg(ctx context.Context, opts *BuildGadgetImageOpts) error {
	// load metadata file
	metadataFile, err := os.Open(opts.MetadataPath)
	if err != nil {
		return fmt.Errorf("opening metadata file: %w", err)
	}
	defer metadataFile.Close()

	metadata := &types.GadgetMetadata{}
	if err := yaml.NewDecoder(metadataFile).Decode(metadata); err != nil {
		return fmt.Errorf("decoding metadata file: %w", err)
	}

	_, statErr := os.Stat(opts.ArtifactHubPkgPath)
	update := statErr == nil

	var ArtifactHubPkgBytes []byte
	if update {
		// load artifacthub-pkg.yml
		ArtifactHubPkgBytes, err = os.ReadFile(opts.ArtifactHubPkgPath)
		if err != nil {
			return fmt.Errorf("reading artifact hub pkg file: %w", err)
		}

		log.Debugf("Artifact hub pkg file found, updating it")
	} else {
		log.Debug("Artifact hub pkg file not found, generating it")

		imageFunc := func() string {
			// Try to guess the image name from the source URL
			githubUsername := "username"
			if strings.HasPrefix(metadata.SourceURL, "https://github.com/") {
				parts := strings.Split(metadata.SourceURL, "/")
				if len(parts) >= 4 {
					githubUsername = parts[3]
				}
			}
			dir := filepath.Dir(opts.MetadataPath)
			if dir == "." {
				dir, _ = os.Getwd()
			}
			dir = filepath.Base(dir)

			dirParts := strings.Split(dir, "_")
			imagePrefix := ""
			if len(dirParts) > 1 {
				imagePrefix = dirParts[0] + "_"
			}
			shortImageName := strings.Replace(metadata.Name, " ", "_", -1)
			if strings.HasPrefix(shortImageName, imagePrefix) {
				imagePrefix = ""
			}
			return fmt.Sprintf("ghcr.io/%s/gadget/%s%s:latest", githubUsername, imagePrefix, shortImageName)
		}

		funcMap := template.FuncMap{
			"image": imageFunc,
		}

		t, err := template.New("artifacthub-pkg.yml").Funcs(funcMap).Parse(ArtifactHubPkgTemplate)
		if err != nil {
			return fmt.Errorf("parsing artifact hub pkg template: %w", err)
		}
		var doc bytes.Buffer
		t.Execute(&doc, metadata)

		ArtifactHubPkgBytes = []byte(doc.String())
	}

	var artifactHubPkg yaml.Node
	err = yaml.Unmarshal(ArtifactHubPkgBytes, &artifactHubPkg)
	if err != nil {
		return fmt.Errorf("unmarshalling artifact hub pkg file: %w\n%s", err, string(ArtifactHubPkgBytes))
	}

	if artifactHubPkg.Kind != yaml.DocumentNode {
		return fmt.Errorf("artifact hub pkg file is not a document")
	}
	if len(artifactHubPkg.Content) == 0 {
		return fmt.Errorf("artifact hub pkg file is empty")
	}
	if artifactHubPkg.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("artifact hub pkg file is not a mapping: %v", artifactHubPkg.Content[0].Kind)
	}
	if len(artifactHubPkg.Content[0].Content)%2 != 0 {
		return fmt.Errorf("artifact hub pkg file is not a mapping: len=%d", len(artifactHubPkg.Content[0].Content))
	}

	for i := 0; i < len(artifactHubPkg.Content[0].Content)/2; i++ {
		key := artifactHubPkg.Content[0].Content[i*2]
		value := artifactHubPkg.Content[0].Content[i*2+1]
		if key.Kind != yaml.ScalarNode {
			continue
		}
		if value.Kind != yaml.ScalarNode {
			continue
		}
		switch key.Value {
		case "name":
			value.Value = metadata.Name
		case "displayName":
			value.Value = metadata.Name
		case "description":
			value.Value = metadata.Description
		case "homepageURL":
			value.Value = metadata.HomepageURL
		case "createdAt":
			value.Value = opts.CreatedDate
		default:
			if ann, ok := metadata.Annotations["artifacthub.io/"+key.Value]; ok {
				value.Value = ann
			}
		}
	}

	marshalled, err := yaml.Marshal(artifactHubPkg.Content[0])
	if err != nil {
		return err
	}

	if err := os.WriteFile(opts.ArtifactHubPkgPath, marshalled, 0o644); err != nil {
		return fmt.Errorf("writing artifact hub pkg file: %w", err)
	}

	// fix owner of created artifact hub pkg file
	if !update {
		if err := fixOwner(opts.ArtifactHubPkgPath, opts.EBPFSourcePath); err != nil {
			log.Warnf("Failed to fix artifact hub pkg file owner: %v", err)
		}
	}

	return nil
}
