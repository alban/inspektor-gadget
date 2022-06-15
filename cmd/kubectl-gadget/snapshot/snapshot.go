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
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	processcollectortypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/process-collector/types"
	socketcollectortypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/socket-collector/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

var SnapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Take a snapshot of a subsystem and print it",
}

type GadgetEvent interface {
	socketcollectortypes.Event | processcollectortypes.Event

	// The Go compiler does not support accessing a struct field x.f where x is
	// of type parameter type even if all types in the type parameter's type set
	// have a field f. We may remove this restriction in Go 1.19. See
	// https://tip.golang.org/doc/go1.18#generics.
	GetBaseEvent() eventtypes.Event
}

type GadgetFlags interface {
	SocketFlags | ProcessFlags
}

// getSnapshotCallback returns the callback that will be called when a snapshot
// gadget finishes without errors and generates a list of results per node. This
// function merges, sorts and print all of them in the requested mode.
func getSnapshotCallback[Event GadgetEvent, Flags GadgetFlags](
	outputConf *utils.OutputConfig,
	gadgetFlags *Flags,
	sortEvents func([]Event, *Flags),
	getColsHeader func(*Flags, []string) string,
	transformEvent func(*Event, *Flags, *utils.OutputConfig) string,
) func(results []gadgetv1alpha1.Trace) error {
	return func(results []gadgetv1alpha1.Trace) error {
		allEvents := []Event{}

		for _, i := range results {
			if len(i.Status.Output) == 0 {
				continue
			}

			var events []Event
			if err := json.Unmarshal([]byte(i.Status.Output), &events); err != nil {
				return utils.WrapInErrUnmarshalOutput(err, i.Status.Output)
			}
			allEvents = append(allEvents, events...)
		}

		sortEvents(allEvents, gadgetFlags)

		switch outputConf.OutputMode {
		case utils.OutputModeJSON:
			b, err := json.MarshalIndent(allEvents, "", "  ")
			if err != nil {
				return utils.WrapInErrMarshalOutput(err)
			}

			fmt.Printf("%s\n", b)
			return nil
		case utils.OutputModeColumns:
			fallthrough
		case utils.OutputModeCustomColumns:
			// In the snapshot gadgets it's possible to use a tabwriter because
			// we have the full list of events to print available, hence the
			// tablewriter is able to determine the columns width. In other
			// gadgets we don't know the size of all columns "a priori", hence
			// we have to do a best effort printing fixed-width columns.
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)

			fmt.Fprintln(w, getColsHeader(gadgetFlags, outputConf.CustomColumns))

			for _, e := range allEvents {
				baseEvent := e.GetBaseEvent()
				if baseEvent.Type != eventtypes.NORMAL {
					utils.ManageSpecialEvent(baseEvent, outputConf.Verbose)
					continue
				}

				fmt.Fprintln(w, transformEvent(&e, gadgetFlags, outputConf))
			}

			w.Flush()
		default:
			return utils.WrapInErrOutputModeNotSupported(outputConf.OutputMode)
		}

		return nil
	}
}

// buildSnapshotColsHeader returns a header with the requested custom columns
// that exist in the availableCols. The columns are separated by taps.
func buildSnapshotColsHeader(availableCols map[string]struct{}, requestedCols []string) string {
	var sb strings.Builder

	for _, col := range requestedCols {
		if _, ok := availableCols[col]; ok {
			sb.WriteString(strings.ToUpper(col))
		}
		sb.WriteRune('\t')
	}

	return sb.String()
}
