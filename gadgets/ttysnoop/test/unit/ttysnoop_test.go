// Copyright 2025 The Inspektor Gadget authors
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

package tests

import (
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

func TestTtysnoopDummy(t *testing.T) {
	// Keep this dummy test because it does not require a new version of vimto
	// with "/dev/pts/ptmx". See:
	// https://github.com/lmb/vimto/pull/26
	gadgettesting.InitUnitTest(t)
	gadgettesting.MinimumKernelVersion(t, "6.1")
	gadgettesting.DummyGadgetTest(t, "ttysnoop")
}

type ExpectedTtysnoopEvent struct {
	Proc utils.Process `json:"proc"`
	Len  int           `json:"len"`
	Buf  string        `json:"buf"`
}

type testDef struct {
	runnerConfig *utilstest.RunnerConfig
	text         string
	validate     func(t *testing.T, info *utilstest.RunnerInfo, events []ExpectedTtysnoopEvent, text string)
}

func TestTtysnoopFull(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	_, err := os.Stat("/dev/pts/ptmx")
	if err != nil {
		t.Skipf("Skipping test: /dev/pts/ptmx not found, this test requires a PTY device. Error: %v", err)
	}

	gadgettesting.MinimumKernelVersion(t, "6.1")

	testCases := map[string]testDef{
		"simple_write": {
			runnerConfig: &utilstest.RunnerConfig{},
			text:         "hello world",
			validate: func(t *testing.T, info *utilstest.RunnerInfo, events []ExpectedTtysnoopEvent, text string) {
				require.Len(t, events, 1, "Expected 1 event but got %d", len(events))
				require.Equal(t, len(text), events[0].Len, "Expected Len %d, got %d", len(text), events[0].Len)
				require.Equal(t, text, events[0].Buf, "Expected Args %q, got %q", text, events[0].Buf)
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, func() error {
					generateEventFromThread(t, testCase.text)
					return nil
				})
				return nil
			}
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedTtysnoopEvent]{
				Image:          "ttysnoop",
				Timeout:        5 * time.Second,
				ParamValues:    api.ParamValues{},
				MntnsFilterMap: utilstest.CreateMntNsFilterMap(t, runner.Info.MountNsID),
				OnGadgetRun:    onGadgetRun,
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()
			testCase.validate(t, runner.Info, gadgetRunner.CapturedEvents, testCase.text)
		})
	}
}

func generateEventFromThread(t *testing.T, text string) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ptmx, tty, err := pty.Open()
	if err != nil {
		// Fails when /dev/pts is not mounted.
		// See https://github.com/lmb/vimto/pull/26
		t.Fatalf("Failed to open pty: %v", err)
	}
	defer ptmx.Close()
	defer tty.Close()

	_, err = ptmx.WriteString(text)
	if err != nil {
		t.Fatalf("Failed to write to pty: %v", err)
	}
}
