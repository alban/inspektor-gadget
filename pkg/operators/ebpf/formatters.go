// Copyright 2024 The Inspektor Gadget authors
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

package ebpfoperator

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/symbolizer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/annotations"
)

const (
	kernelStackTargetNameAnnotation = "ebpf.formatter.kstack"
	userStackTargetNameAnnotation   = "ebpf.formatter.ustack"
	enumTargetNameAnnotation        = "ebpf.formatter.enum"
	enumBitfieldSeparatorAnnotation = "ebpf.formatter.bitfield.separator"
)

func byteSliceAsUint64(in []byte, signed bool, ds datasource.DataSource) uint64 {
	if signed {
		switch len(in) {
		case 1:
			return uint64(int8(in[0]))
		case 2:
			return uint64(int16(ds.ByteOrder().Uint16(in)))
		case 4:
			return uint64(int32(ds.ByteOrder().Uint32(in)))
		case 8:
			return uint64(int64(ds.ByteOrder().Uint64(in)))
		}
	}

	switch len(in) {
	case 1:
		return uint64(in[0])
	case 2:
		return uint64(ds.ByteOrder().Uint16(in))
	case 4:
		return uint64(ds.ByteOrder().Uint32(in))
	case 8:
		return uint64(ds.ByteOrder().Uint64(in))
	}

	return 0
}

func (i *ebpfInstance) initEnumFormatter(gadgetCtx operators.GadgetContext) error {
	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		i.logger.Warnf("Kernel BTF information not available. Enums won't be resolved to strings")
	}

	for _, ds := range gadgetCtx.GetDataSources() {
		var formatters []func(ds datasource.DataSource, data datasource.Data) error

		for _, en := range i.enums {
			enum := en.Enum
			name := en.memberName
			in := ds.GetField(name)
			if in == nil {
				continue
			}
			in.SetHidden(true, false)

			if btfSpec != nil {
				kernelEnum := &btf.Enum{}
				if err = btfSpec.TypeByName(enum.Name, &kernelEnum); err == nil {
					// Use kernel enum if found
					enum = kernelEnum
				}
			}

			targetName, err := annotations.GetTargetNameFromAnnotation(i.logger, "enum", in, enumTargetNameAnnotation)
			if err != nil {
				i.logger.Warnf("Failed to get target name for enum field %q: %v", in.Name(), err)
				continue
			}

			out, err := ds.AddField(targetName, api.Kind_String, datasource.WithSameParentAs(in))
			if err != nil {
				return err
			}

			var formatter func(ds datasource.DataSource, data datasource.Data) error

			isBitField := strings.HasSuffix(enum.Name, "_set")
			if isBitField {
				separator := in.Annotations()[enumBitfieldSeparatorAnnotation]
				if separator == "" {
					separator = "|"
				}

				formatter = func(ds datasource.DataSource, data datasource.Data) error {
					inBytes := in.Get(data)
					val := byteSliceAsUint64(inBytes, enum.Signed, ds)

					var arr []string
					for _, v := range enum.Values {
						if val&v.Value == v.Value {
							arr = append(arr, v.Name)
						}
					}
					out.PutString(data, strings.Join(arr, separator))
					return nil
				}
			} else {
				formatter = func(ds datasource.DataSource, data datasource.Data) error {
					// TODO: lookup table?
					inBytes := in.Get(data)
					val := byteSliceAsUint64(inBytes, enum.Signed, ds)
					for _, v := range enum.Values {
						if val == v.Value {
							out.Set(data, []byte(v.Name))
							return nil
						}
					}
					out.Set(data, []byte("UNKNOWN"))
					return nil
				}
			}

			formatters = append(formatters, formatter)
		}

		if len(formatters) > 0 {
			i.formatters[ds] = formatters
		}
	}

	return nil
}

func (i *ebpfInstance) initStackConverter(gadgetCtx operators.GadgetContext) error {
	var kernelSymbolResolver *kallsyms.KAllSyms = nil
	for _, ds := range gadgetCtx.GetDataSources() {
		for _, in := range ds.GetFieldsWithTag("type:" + ebpftypes.KernelStackTypeName) {
			if in == nil {
				continue
			}
			in.SetHidden(true, false)

			if kernelSymbolResolver == nil {
				var err error
				kernelSymbolResolver, err = kallsyms.NewKAllSyms()
				if err != nil {
					return err
				}
			}

			if i.stackIdMap == nil {
				return errors.New("kernel stack map is not initialized but used. " +
					"if you are using `gadget_kernel_stack` as event field, " +
					"try to include <gadget/kernel_stack_map.h>")
			}

			targetName, err := annotations.GetTargetNameFromAnnotation(i.logger, "kstack", in, kernelStackTargetNameAnnotation)
			if err != nil {
				i.logger.Warnf("Failed to get target name for enum field %q: %v", in.Name(), err)
				continue
			}
			out, err := ds.AddField(targetName, api.Kind_String, datasource.WithSameParentAs(in))
			if err != nil {
				return err
			}
			converter := func(ds datasource.DataSource, data datasource.Data) error {
				inBytes := in.Get(data)
				stackId := ds.ByteOrder().Uint32(inBytes)

				stack := [PerfMaxStackDepth]uint64{}
				err = i.stackIdMap.Lookup(stackId, &stack)
				if err != nil {
					i.logger.Warnf("stack with ID %d is lost: %s", stackId, err.Error())
					out.Set(data, []byte{})
					return nil
				}

				outString := ""
				for depth, addr := range stack {
					if addr == 0 {
						break
					}
					outString += fmt.Sprintf("[%d]%s; ", depth, kernelSymbolResolver.LookupByInstructionPointer(addr))
				}

				out.Set(data, []byte(outString))
				return nil
			}
			i.formatters[ds] = append(i.formatters[ds], converter)
		}
		for _, in := range ds.GetFieldsWithTag("type:" + ebpftypes.UserStackTypeName) {
			if in == nil {
				continue
			}
			in.SetHidden(true, false)

			pidField := ds.GetField("proc.pid")
			if pidField == nil {
				gadgetCtx.Logger().Warnf("no pid field found")
				continue
			}

			inodeField := ds.GetField("inode")
			if inodeField == nil {
				gadgetCtx.Logger().Warnf("no inode field found")
				continue
			}
			mtimeSecField := ds.GetField("mtime_sec")
			if mtimeSecField == nil {
				gadgetCtx.Logger().Warnf("no mtime_sec field found")
				continue
			}
			mtimeNsecField := ds.GetField("mtime_nsec")
			if mtimeNsecField == nil {
				gadgetCtx.Logger().Warnf("no mtime_nsec field found")
				continue
			}

			if i.userStackMap == nil {
				return errors.New("user stack map is not initialized but used. " +
					"if you are using `gadget_user_stack` as event field, " +
					"try to include <gadget/user_stack_map.h>")
			}

			targetName, err := annotations.GetTargetNameFromAnnotation(i.logger, "ustack", in, userStackTargetNameAnnotation)
			if err != nil {
				i.logger.Warnf("Failed to get target name for enum field %q: %v", in.Name(), err)
				continue
			}
			out, err := ds.AddField(targetName, api.Kind_String, datasource.WithSameParentAs(in))
			if err != nil {
				return err
			}
			converter := func(ds datasource.DataSource, data datasource.Data) error {
				inBytes := in.Get(data)
				stackId := ds.ByteOrder().Uint32(inBytes)
				pid, _ := pidField.Uint32(data)
				inode, _ := inodeField.Uint64(data)
				mtimeSec, _ := mtimeSecField.Uint64(data)
				mtimeNsec, _ := mtimeNsecField.Uint32(data)

				// If user stacks are disabled
				if stackId == math.MaxUint32 {
					out.Set(data, []byte{})
					return nil
				}

				stack := [PerfMaxStackDepth]uint64{}
				err = i.userStackMap.Lookup(stackId, &stack)
				if err != nil {
					i.logger.Warnf("stack with ID %d is lost: %s", stackId, err.Error())
					out.Set(data, []byte{})
					return nil
				}

				outString := ""
				addrs := make([]uint64, 0, len(stack))
				for _, addr := range stack {
					if addr == 0 {
						break
					}
					addrs = append(addrs, addr)
				}

				exeKey := symbolizer.GenKey(inode, int64(mtimeSec), mtimeNsec)
				symbols, err := i.symbolizer.Resolve(pid, exeKey, addrs)
				if err != nil {
					out.Set(data, []byte(err.Error()))
					return nil
				}

				for i, symbol := range symbols {
					outString += fmt.Sprintf("[%d]%s; ", i, symbol)
				}

				out.Set(data, []byte(outString))
				return nil
			}
			i.formatters[ds] = append(i.formatters[ds], converter)
		}
	}
	return nil
}

func (i *ebpfInstance) initFormatters(gadgetCtx operators.GadgetContext) error {
	if err := i.initEnumFormatter(gadgetCtx); err != nil {
		return fmt.Errorf("initializing enum formatter: %w", err)
	}

	if err := i.initStackConverter(gadgetCtx); err != nil {
		return fmt.Errorf("initializing stack converters: %w", err)
	}

	return nil
}
