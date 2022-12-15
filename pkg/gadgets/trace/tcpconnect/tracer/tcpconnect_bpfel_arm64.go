// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64
// +build arm64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type tcpconnectEvent struct {
	SaddrV6   [16]uint8
	DaddrV6   [16]uint8
	Task      [16]uint8
	Timestamp uint64
	Af        uint32
	Pid       uint32
	Uid       uint32
	Dport     uint16
	_         [2]byte
	MntnsId   uint64
}

type tcpconnectIpv4FlowKey struct {
	Saddr uint32
	Daddr uint32
	Dport uint16
	_     [2]byte
}

type tcpconnectIpv6FlowKey struct {
	Saddr [16]uint8
	Daddr [16]uint8
	Dport uint16
}

// loadTcpconnect returns the embedded CollectionSpec for tcpconnect.
func loadTcpconnect() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TcpconnectBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load tcpconnect: %w", err)
	}

	return spec, err
}

// loadTcpconnectObjects loads tcpconnect and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*tcpconnectObjects
//	*tcpconnectPrograms
//	*tcpconnectMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTcpconnectObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTcpconnect()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// tcpconnectSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcpconnectSpecs struct {
	tcpconnectProgramSpecs
	tcpconnectMapSpecs
}

// tcpconnectSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcpconnectProgramSpecs struct {
	IgTcpcV4CoE *ebpf.ProgramSpec `ebpf:"ig_tcpc_v4_co_e"`
	IgTcpcV4CoX *ebpf.ProgramSpec `ebpf:"ig_tcpc_v4_co_x"`
	IgTcpcV6CoE *ebpf.ProgramSpec `ebpf:"ig_tcpc_v6_co_e"`
	IgTcpcV6CoX *ebpf.ProgramSpec `ebpf:"ig_tcpc_v6_co_x"`
}

// tcpconnectMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcpconnectMapSpecs struct {
	Events        *ebpf.MapSpec `ebpf:"events"`
	Ipv4Count     *ebpf.MapSpec `ebpf:"ipv4_count"`
	Ipv6Count     *ebpf.MapSpec `ebpf:"ipv6_count"`
	MountNsFilter *ebpf.MapSpec `ebpf:"mount_ns_filter"`
	Sockets       *ebpf.MapSpec `ebpf:"sockets"`
}

// tcpconnectObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTcpconnectObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcpconnectObjects struct {
	tcpconnectPrograms
	tcpconnectMaps
}

func (o *tcpconnectObjects) Close() error {
	return _TcpconnectClose(
		&o.tcpconnectPrograms,
		&o.tcpconnectMaps,
	)
}

// tcpconnectMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTcpconnectObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcpconnectMaps struct {
	Events        *ebpf.Map `ebpf:"events"`
	Ipv4Count     *ebpf.Map `ebpf:"ipv4_count"`
	Ipv6Count     *ebpf.Map `ebpf:"ipv6_count"`
	MountNsFilter *ebpf.Map `ebpf:"mount_ns_filter"`
	Sockets       *ebpf.Map `ebpf:"sockets"`
}

func (m *tcpconnectMaps) Close() error {
	return _TcpconnectClose(
		m.Events,
		m.Ipv4Count,
		m.Ipv6Count,
		m.MountNsFilter,
		m.Sockets,
	)
}

// tcpconnectPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTcpconnectObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcpconnectPrograms struct {
	IgTcpcV4CoE *ebpf.Program `ebpf:"ig_tcpc_v4_co_e"`
	IgTcpcV4CoX *ebpf.Program `ebpf:"ig_tcpc_v4_co_x"`
	IgTcpcV6CoE *ebpf.Program `ebpf:"ig_tcpc_v6_co_e"`
	IgTcpcV6CoX *ebpf.Program `ebpf:"ig_tcpc_v6_co_x"`
}

func (p *tcpconnectPrograms) Close() error {
	return _TcpconnectClose(
		p.IgTcpcV4CoE,
		p.IgTcpcV4CoX,
		p.IgTcpcV6CoE,
		p.IgTcpcV6CoX,
	)
}

func _TcpconnectClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed tcpconnect_bpfel_arm64.o
var _TcpconnectBytes []byte
