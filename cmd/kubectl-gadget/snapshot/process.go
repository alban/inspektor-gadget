// Copyright 2019-2022 The Inspektor Gadget authors
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

package snapshot

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/process-collector/types"
)

type ProcessFlags struct {
	paramThreads bool
}

func init() {
	var commonFlags utils.CommonFlags

	processCmd := initProcessCmd(&commonFlags)
	utils.AddCommonFlags(processCmd, &commonFlags)
	SnapshotCmd.AddCommand(processCmd)
}

func initProcessCmd(commonFlags *utils.CommonFlags) *cobra.Command {
	var processFlags ProcessFlags

	cmd := &cobra.Command{
		Use:   "process",
		Short: "Gather information about running processes",
		RunE: func(cmd *cobra.Command, args []string) error {
			config := &utils.TraceConfig{
				GadgetName:       "process-collector",
				Operation:        "collect",
				TraceOutputMode:  "Status",
				TraceOutputState: "Completed",
				CommonFlags:      commonFlags,
			}

			callback := getSnapshotCallback(&commonFlags.OutputConf, &processFlags,
				sortProcessEvents, getProcessColsHeader, transformProcessEvent)

			return utils.RunTraceAndPrintStatusOutput(config, callback)
		},
	}

	cmd.PersistentFlags().BoolVarP(
		&processFlags.paramThreads,
		"threads",
		"t",
		false,
		"Show all threads",
	)

	return cmd
}

// getProcessColsHeader returns a header with the default list of columns
// when it is not requested to use a subset of custom columns.
func getProcessColsHeader(processFlags *ProcessFlags, requestedCols []string) string {
	availableCols := map[string]struct{}{
		"node":      {},
		"namespace": {},
		"pod":       {},
		"container": {},
		"comm":      {},
		"tgid":      {},
		"pid":       {},
	}

	if len(requestedCols) == 0 {
		requestedCols = []string{"node", "namespace", "pod", "container", "comm", "pid"}
		if processFlags.paramThreads {
			requestedCols = []string{"node", "namespace", "pod", "container", "comm", "tgid", "pid"}
		}
	}

	return buildSnapshotColsHeader(availableCols, requestedCols)
}

// transformProcessEvent is called to transform an event to columns
// format according to the parameters.
func transformProcessEvent(e *types.Event, processFlags *ProcessFlags, outputConf *utils.OutputConfig) string {
	var sb strings.Builder

	switch outputConf.OutputMode {
	case utils.OutputModeColumns:
		if processFlags.paramThreads {
			sb.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%d\t%d",
				e.Node, e.Namespace, e.Pod, e.Container,
				e.Command, e.Tgid, e.Pid))
		} else {
			sb.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%d",
				e.Node, e.Namespace, e.Pod, e.Container,
				e.Command, e.Pid))
		}
	case utils.OutputModeCustomColumns:
		for _, col := range outputConf.CustomColumns {
			switch col {
			case "node":
				sb.WriteString(fmt.Sprintf("%s", e.Node))
			case "namespace":
				sb.WriteString(fmt.Sprintf("%s", e.Namespace))
			case "pod":
				sb.WriteString(fmt.Sprintf("%s", e.Pod))
			case "container":
				sb.WriteString(fmt.Sprintf("%s", e.Container))
			case "comm":
				sb.WriteString(fmt.Sprintf("%s", e.Command))
			case "tgid":
				sb.WriteString(fmt.Sprintf("%d", e.Tgid))
			case "pid":
				sb.WriteString(fmt.Sprintf("%d", e.Pid))
			}
			sb.WriteRune('\t')
		}
	}

	return sb.String()
}

func sortProcessEvents(allProcesses []types.Event, processFlags *ProcessFlags) {
	if !processFlags.paramThreads {
		allProcessesTrimmed := []types.Event{}
		for _, i := range allProcesses {
			if i.Tgid == i.Pid {
				allProcessesTrimmed = append(allProcessesTrimmed, i)
			}
		}
		allProcesses = allProcessesTrimmed
	}

	sort.Slice(allProcesses, func(i, j int) bool {
		pi, pj := allProcesses[i], allProcesses[j]
		switch {
		case pi.Node != pj.Node:
			return pi.Node < pj.Node
		case pi.Namespace != pj.Namespace:
			return pi.Namespace < pj.Namespace
		case pi.Pod != pj.Pod:
			return pi.Pod < pj.Pod
		case pi.Container != pj.Container:
			return pi.Container < pj.Container
		case pi.Command != pj.Command:
			return pi.Command < pj.Command
		case pi.Tgid != pj.Tgid:
			return pi.Tgid < pj.Tgid
		default:
			return pi.Pid < pj.Pid
		}
	})
}
