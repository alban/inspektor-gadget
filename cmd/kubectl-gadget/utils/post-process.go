// Copyright 2019-2021 The Inspektor Gadget authors
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

package utils

import (
	"fmt"
	"io"
	"strings"
)

type PostProcess struct {
	OutStreams []*postProcessSingle
	ErrStreams []*postProcessSingle
}

type postProcessSingle struct {
	orig       io.Writer
	transform  func(string) string
	buffer     string // buffer to save incomplete strings
	jsonOutput bool
	verbose    bool
}

func NewPostProcess(n int, outStream io.Writer, errStream io.Writer, params *CommonFlags, transform func(string) string) *PostProcess {
	p := &PostProcess{
		OutStreams: make([]*postProcessSingle, n),
		ErrStreams: make([]*postProcessSingle, n),
	}

	jsonOutput := false
	verbose := false
	if params != nil {
		jsonOutput = params.JsonOutput
		verbose = params.Verbose
	}

	for i := 0; i < n; i++ {
		p.OutStreams[i] = &postProcessSingle{
			orig:       outStream,
			transform:  transform,
			buffer:     "",
			jsonOutput: jsonOutput,
			verbose:    verbose,
		}

		p.ErrStreams[i] = &postProcessSingle{
			orig:      errStream,
			transform: transform,
			buffer:    "",
		}
	}

	return p
}

func (post *postProcessSingle) Write(p []byte) (n int, err error) {
	asStr := post.buffer + string(p)

	lines := strings.Split(asStr, "\n")
	if len(lines) == 0 {
		return len(p), nil
	}

	// Print all complete lines
	for _, line := range lines[0 : len(lines)-1] {
		if post.transform != nil {
			line = post.transform(line)
		}
		if line != "" {
			fmt.Fprintf(post.orig, "%s\n", line)
		}
	}

	post.buffer = lines[len(lines)-1] // Buffer last line to print in next iteration

	return len(p), err
}
