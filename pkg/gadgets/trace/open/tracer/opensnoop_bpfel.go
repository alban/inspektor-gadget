// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || loong64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type opensnoopEvent struct {
	Timestamp uint64
	Pid       uint32
	Uid       uint32
	Gid       uint32
	_         [4]byte
	MntnsId   uint64
	CgroupId  uint64
	Ret       int32
	Flags     int32
	Mode      uint16
	Comm      [16]uint8
	Fname     [255]uint8
	FullFname [4096]uint8
	_         [7]byte
}

// loadOpensnoop returns the embedded CollectionSpec for opensnoop.
func loadOpensnoop() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_OpensnoopBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load opensnoop: %w", err)
	}

	return spec, err
}

// loadOpensnoopObjects loads opensnoop and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*opensnoopObjects
//	*opensnoopPrograms
//	*opensnoopMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadOpensnoopObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadOpensnoop()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// opensnoopSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type opensnoopSpecs struct {
	opensnoopProgramSpecs
	opensnoopMapSpecs
}

// opensnoopSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type opensnoopProgramSpecs struct {
	IgOpenE   *ebpf.ProgramSpec `ebpf:"ig_open_e"`
	IgOpenX   *ebpf.ProgramSpec `ebpf:"ig_open_x"`
	IgOpenatE *ebpf.ProgramSpec `ebpf:"ig_openat_e"`
	IgOpenatX *ebpf.ProgramSpec `ebpf:"ig_openat_x"`
}

// opensnoopMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type opensnoopMapSpecs struct {
	Bufs                  *ebpf.MapSpec `ebpf:"bufs"`
	Events                *ebpf.MapSpec `ebpf:"events"`
	GadgetCgroupFilterMap *ebpf.MapSpec `ebpf:"gadget_cgroup_filter_map"`
	GadgetMntnsFilterMap  *ebpf.MapSpec `ebpf:"gadget_mntns_filter_map"`
	Start                 *ebpf.MapSpec `ebpf:"start"`
}

// opensnoopObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadOpensnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type opensnoopObjects struct {
	opensnoopPrograms
	opensnoopMaps
}

func (o *opensnoopObjects) Close() error {
	return _OpensnoopClose(
		&o.opensnoopPrograms,
		&o.opensnoopMaps,
	)
}

// opensnoopMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadOpensnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type opensnoopMaps struct {
	Bufs                  *ebpf.Map `ebpf:"bufs"`
	Events                *ebpf.Map `ebpf:"events"`
	GadgetCgroupFilterMap *ebpf.Map `ebpf:"gadget_cgroup_filter_map"`
	GadgetMntnsFilterMap  *ebpf.Map `ebpf:"gadget_mntns_filter_map"`
	Start                 *ebpf.Map `ebpf:"start"`
}

func (m *opensnoopMaps) Close() error {
	return _OpensnoopClose(
		m.Bufs,
		m.Events,
		m.GadgetCgroupFilterMap,
		m.GadgetMntnsFilterMap,
		m.Start,
	)
}

// opensnoopPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadOpensnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type opensnoopPrograms struct {
	IgOpenE   *ebpf.Program `ebpf:"ig_open_e"`
	IgOpenX   *ebpf.Program `ebpf:"ig_open_x"`
	IgOpenatE *ebpf.Program `ebpf:"ig_openat_e"`
	IgOpenatX *ebpf.Program `ebpf:"ig_openat_x"`
}

func (p *opensnoopPrograms) Close() error {
	return _OpensnoopClose(
		p.IgOpenE,
		p.IgOpenX,
		p.IgOpenatE,
		p.IgOpenatX,
	)
}

func _OpensnoopClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed opensnoop_bpfel.o
var _OpensnoopBytes []byte
