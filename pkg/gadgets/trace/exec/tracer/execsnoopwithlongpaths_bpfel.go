// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type execsnoopWithLongPathsBufT struct{ Buf [32768]uint8 }

type execsnoopWithLongPathsEvent struct {
	MntnsId     uint64
	Timestamp   uint64
	Pid         uint32
	Ppid        uint32
	Uid         uint32
	Gid         uint32
	Loginuid    uint32
	Sessionid   uint32
	Retval      int32
	ArgsCount   int32
	UpperLayer  bool
	PupperLayer bool
	_           [2]byte
	ArgsSize    uint32
	Comm        [16]uint8
	Pcomm       [16]uint8
	Cwd         [4096]uint8
	Exepath     [4096]uint8
	Args        [7680]uint8
}

// loadExecsnoopWithLongPaths returns the embedded CollectionSpec for execsnoopWithLongPaths.
func loadExecsnoopWithLongPaths() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ExecsnoopWithLongPathsBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load execsnoopWithLongPaths: %w", err)
	}

	return spec, err
}

// loadExecsnoopWithLongPathsObjects loads execsnoopWithLongPaths and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*execsnoopWithLongPathsObjects
//	*execsnoopWithLongPathsPrograms
//	*execsnoopWithLongPathsMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadExecsnoopWithLongPathsObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadExecsnoopWithLongPaths()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// execsnoopWithLongPathsSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type execsnoopWithLongPathsSpecs struct {
	execsnoopWithLongPathsProgramSpecs
	execsnoopWithLongPathsMapSpecs
}

// execsnoopWithLongPathsSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type execsnoopWithLongPathsProgramSpecs struct {
	IgExecveE *ebpf.ProgramSpec `ebpf:"ig_execve_e"`
	IgExecveX *ebpf.ProgramSpec `ebpf:"ig_execve_x"`
}

// execsnoopWithLongPathsMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type execsnoopWithLongPathsMapSpecs struct {
	Bufs                 *ebpf.MapSpec `ebpf:"bufs"`
	Events               *ebpf.MapSpec `ebpf:"events"`
	Execs                *ebpf.MapSpec `ebpf:"execs"`
	GadgetMntnsFilterMap *ebpf.MapSpec `ebpf:"gadget_mntns_filter_map"`
	IgPidByTgid          *ebpf.MapSpec `ebpf:"ig_pid_by_tgid"`
}

// execsnoopWithLongPathsObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadExecsnoopWithLongPathsObjects or ebpf.CollectionSpec.LoadAndAssign.
type execsnoopWithLongPathsObjects struct {
	execsnoopWithLongPathsPrograms
	execsnoopWithLongPathsMaps
}

func (o *execsnoopWithLongPathsObjects) Close() error {
	return _ExecsnoopWithLongPathsClose(
		&o.execsnoopWithLongPathsPrograms,
		&o.execsnoopWithLongPathsMaps,
	)
}

// execsnoopWithLongPathsMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadExecsnoopWithLongPathsObjects or ebpf.CollectionSpec.LoadAndAssign.
type execsnoopWithLongPathsMaps struct {
	Bufs                 *ebpf.Map `ebpf:"bufs"`
	Events               *ebpf.Map `ebpf:"events"`
	Execs                *ebpf.Map `ebpf:"execs"`
	GadgetMntnsFilterMap *ebpf.Map `ebpf:"gadget_mntns_filter_map"`
	IgPidByTgid          *ebpf.Map `ebpf:"ig_pid_by_tgid"`
}

func (m *execsnoopWithLongPathsMaps) Close() error {
	return _ExecsnoopWithLongPathsClose(
		m.Bufs,
		m.Events,
		m.Execs,
		m.GadgetMntnsFilterMap,
		m.IgPidByTgid,
	)
}

// execsnoopWithLongPathsPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadExecsnoopWithLongPathsObjects or ebpf.CollectionSpec.LoadAndAssign.
type execsnoopWithLongPathsPrograms struct {
	IgExecveE *ebpf.Program `ebpf:"ig_execve_e"`
	IgExecveX *ebpf.Program `ebpf:"ig_execve_x"`
}

func (p *execsnoopWithLongPathsPrograms) Close() error {
	return _ExecsnoopWithLongPathsClose(
		p.IgExecveE,
		p.IgExecveX,
	)
}

func _ExecsnoopWithLongPathsClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed execsnoopwithlongpaths_bpfel.o
var _ExecsnoopWithLongPathsBytes []byte
