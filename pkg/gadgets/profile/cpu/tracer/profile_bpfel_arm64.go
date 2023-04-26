// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type profileKeyT struct {
	KernelIp    uint64
	MntnsId     uint64
	Pid         uint32
	UserStackId int32
	KernStackId int32
	Name        [16]uint8
	_           [4]byte
}

// loadProfile returns the embedded CollectionSpec for profile.
func loadProfile() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ProfileBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load profile: %w", err)
	}

	return spec, err
}

// loadProfileObjects loads profile and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*profileObjects
//	*profilePrograms
//	*profileMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadProfileObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadProfile()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// profileSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type profileSpecs struct {
	profileProgramSpecs
	profileMapSpecs
}

// profileSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type profileProgramSpecs struct {
	IgProfCpu *ebpf.ProgramSpec `ebpf:"ig_prof_cpu"`
}

// profileMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type profileMapSpecs struct {
	Counts               *ebpf.MapSpec `ebpf:"counts"`
	GadgetMntnsFilterMap *ebpf.MapSpec `ebpf:"gadget_mntns_filter_map"`
	Stackmap             *ebpf.MapSpec `ebpf:"stackmap"`
}

// profileObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadProfileObjects or ebpf.CollectionSpec.LoadAndAssign.
type profileObjects struct {
	profilePrograms
	profileMaps
}

func (o *profileObjects) Close() error {
	return _ProfileClose(
		&o.profilePrograms,
		&o.profileMaps,
	)
}

// profileMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadProfileObjects or ebpf.CollectionSpec.LoadAndAssign.
type profileMaps struct {
	Counts               *ebpf.Map `ebpf:"counts"`
	GadgetMntnsFilterMap *ebpf.Map `ebpf:"gadget_mntns_filter_map"`
	Stackmap             *ebpf.Map `ebpf:"stackmap"`
}

func (m *profileMaps) Close() error {
	return _ProfileClose(
		m.Counts,
		m.GadgetMntnsFilterMap,
		m.Stackmap,
	)
}

// profilePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadProfileObjects or ebpf.CollectionSpec.LoadAndAssign.
type profilePrograms struct {
	IgProfCpu *ebpf.Program `ebpf:"ig_prof_cpu"`
}

func (p *profilePrograms) Close() error {
	return _ProfileClose(
		p.IgProfCpu,
	)
}

func _ProfileClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed profile_bpfel_arm64.o
var _ProfileBytes []byte
