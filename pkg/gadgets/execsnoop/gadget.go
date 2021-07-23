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

package execsnoop

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
)

type Trace struct {
	started bool
	cmd     *exec.Cmd
}

type TraceFactory struct {
	mu     sync.Mutex
	traces map[string]*Trace
}

func (f *TraceFactory) LookupOrCreate(name types.NamespacedName) gadgets.Trace {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.traces == nil {
		f.traces = make(map[string]*Trace)
	}
	trace, ok := f.traces[name.String()]
	if ok {
		return trace
	}
	trace = &Trace{}
	f.traces[name.String()] = trace

	return trace
}

func (f *TraceFactory) Delete(name types.NamespacedName) error {
	log.Infof("Deleting %s", name.String())
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.traces[name.String()]
	if !ok {
		log.Infof("Deleting %s: does not exist", name.String())
		return nil
	}
	if t.started {
		t.cmd.Process.Kill()
		t.cmd.Wait()
	}
	delete(f.traces, name.String())
	return nil
}

func (t *Trace) Operation(trace *gadgetv1alpha1.Trace, operation string, params map[string]string) {
	if trace.ObjectMeta.Namespace != gadgets.TRACE_DEFAULT_NAMESPACE {
		trace.Status.OperationError = fmt.Sprintf("This gadget only accepts operations on traces in the %s namespace", gadgets.TRACE_DEFAULT_NAMESPACE)
		return
	}
	switch operation {
	case "start":
		t.start(trace)
	case "stop":
		t.stop(trace)
	default:
		trace.Status.OperationError = fmt.Sprintf("Unknown operation %q", operation)
	}
}

func (t *Trace) start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.OperationError = ""
		trace.Status.State = "Started"
		return
	}

	if trace.Spec.OutputMode != "File" {
		trace.Status.OperationError = fmt.Sprintf("Output mode %q not supported for execsnoop", trace.Spec.OutputMode)
		trace.Status.State = ""
		return
	}

	if trace.Spec.OutputFile == "" {
		trace.Status.OperationError = "OutputFile is missing"
		trace.Status.State = ""
		return
	}

	mntnsMapPath := gadgets.TracePinPath(trace.Namespace, trace.Name)

	t.cmd = exec.Command("/usr/share/bcc/tools/execsnoop", "--json",
		"--mntnsmap", mntnsMapPath, "--file", trace.Spec.OutputFile)
	err := t.cmd.Start()
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to start: %s", err)
		return
	}
	t.started = true

	trace.Status.OperationError = ""
	trace.Status.State = "Started"
	return
}

func (t *Trace) stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}
	err := t.cmd.Process.Signal(syscall.SIGINT)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to send SIGINT to process: %s", err)
		return
	}

	err = t.cmd.Wait()
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("Failed to wait for process: %s", err)
		return
	}
	t.cmd = nil
	t.started = false

	trace.Status.OperationError = ""
	trace.Status.State = "Completed"
	return
}
