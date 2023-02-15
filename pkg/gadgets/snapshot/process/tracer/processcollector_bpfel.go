// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadProcessCollector returns the embedded CollectionSpec for processCollector.
func loadProcessCollector() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ProcessCollectorBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load processCollector: %w", err)
	}

	return spec, err
}

// loadProcessCollectorObjects loads processCollector and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*processCollectorObjects
//	*processCollectorPrograms
//	*processCollectorMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadProcessCollectorObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadProcessCollector()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// processCollectorSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type processCollectorSpecs struct {
	processCollectorProgramSpecs
	processCollectorMapSpecs
}

// processCollectorSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type processCollectorProgramSpecs struct {
	IgSnapProc *ebpf.ProgramSpec `ebpf:"ig_snap_proc"`
}

// processCollectorMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type processCollectorMapSpecs struct {
	MountNsFilter *ebpf.MapSpec `ebpf:"mount_ns_filter"`
}

// processCollectorObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadProcessCollectorObjects or ebpf.CollectionSpec.LoadAndAssign.
type processCollectorObjects struct {
	processCollectorPrograms
	processCollectorMaps
}

func (o *processCollectorObjects) Close() error {
	return _ProcessCollectorClose(
		&o.processCollectorPrograms,
		&o.processCollectorMaps,
	)
}

// processCollectorMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadProcessCollectorObjects or ebpf.CollectionSpec.LoadAndAssign.
type processCollectorMaps struct {
	MountNsFilter *ebpf.Map `ebpf:"mount_ns_filter"`
}

func (m *processCollectorMaps) Close() error {
	return _ProcessCollectorClose(
		m.MountNsFilter,
	)
}

// processCollectorPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadProcessCollectorObjects or ebpf.CollectionSpec.LoadAndAssign.
type processCollectorPrograms struct {
	IgSnapProc *ebpf.Program `ebpf:"ig_snap_proc"`
}

func (p *processCollectorPrograms) Close() error {
	return _ProcessCollectorClose(
		p.IgSnapProc,
	)
}

func _ProcessCollectorClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed processcollector_bpfel.o
var _ProcessCollectorBytes []byte
