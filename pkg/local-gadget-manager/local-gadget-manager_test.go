// Copyright 2021 The Inspektor Gadget authors
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

package localgadgetmanager

import (
	"flag"
	"os"
	"testing"

	"github.com/kinvolk/inspektor-gadget/pkg/runcfanotify"
)

var rootTest = flag.Bool("root-test", false, "enable tests requiring root")

func TestBasic(t *testing.T) {
	if !*rootTest {
		t.Skip("skipping test requiring root.")
	}
	localGadgetManager, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to start local gadget manager: %s", err)
	}
	gadgets := localGadgetManager.ListGadgets()
	if len(gadgets) == 0 {
		t.Fatalf("Failed to get any gadgets")
	}
}

func TestSeccomp(t *testing.T) {
	if !*rootTest {
		t.Skip("skipping test requiring root.")
	}
	localGadgetManager, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to start local gadget manager: %s", err)
	}
	err = localGadgetManager.AddTracer("seccomp", "my-tracer", "")
	if err != nil {
		t.Fatalf("Failed to create tracer: %s", err)
	}
	err = localGadgetManager.Operation("my-tracer", "start")
	if err != nil {
		t.Fatalf("Failed to start the tracer: %s", err)
	}
	err = localGadgetManager.Operation("my-tracer", "stop")
	if err != nil {
		t.Fatalf("Failed to stop the tracer: %s", err)
	}
}

func TestCollector(t *testing.T) {
	if !*rootTest {
		t.Skip("skipping test requiring root.")
	}
	localGadgetManager, err := NewManager()
	if err != nil {
		t.Fatalf("Failed to start local gadget manager: %s", err)
	}
	fakeContainer := runcfanotify.ContainerEvent{
		ContainerID:  "my-container",
		ContainerPID: uint32(os.Getpid()),
	}
	localGadgetManager.AddContainer(fakeContainer)

	err = localGadgetManager.AddTracer("socket-collector", "my-tracer1", "my-container")
	if err != nil {
		t.Fatalf("Failed to create tracer: %s", err)
	}
	err = localGadgetManager.Operation("my-tracer1", "start")
	if err != nil {
		t.Fatalf("Failed to start the tracer: %s", err)
	}

	err = localGadgetManager.AddTracer("process-collector", "my-tracer2", "my-container")
	if err != nil {
		t.Fatalf("Failed to create tracer: %s", err)
	}
	err = localGadgetManager.Operation("my-tracer2", "start")
	if err != nil {
		t.Fatalf("Failed to start the tracer: %s", err)
	}
}
