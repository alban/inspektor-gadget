// Copyright 2023 The Inspektor Gadget authors
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

// Package systemdresolver provides an operator that enriches events by
// resolving cgroupids to systemd unit names
package systemdresolver

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	OperatorName         = "SystemdResolver"
	OperatorInstanceName = "SystemdResolverInstance"
)

type SystemdResolverInterface interface {
	GetCgroupID() uint64
	SetSystemdName(name string)
}

type SystemdResolver struct {
	systemdCache *common.SystemdCache
}

func (k *SystemdResolver) Name() string {
	return OperatorName
}

func (k *SystemdResolver) Description() string {
	return "SystemdResolver resolves cgroup ids to systemd unit names"
}

func (k *SystemdResolver) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (k *SystemdResolver) ParamDescs() params.ParamDescs {
	return nil
}

func (k *SystemdResolver) Dependencies() []string {
	return nil
}

func (k *SystemdResolver) CanOperateOn(gadget gadgets.GadgetDesc) bool {
	_, hasSystemdResolverInterface := gadget.EventPrototype().(SystemdResolverInterface)
	return hasSystemdResolverInterface
}

func (k *SystemdResolver) Init(params *params.Params) error {
	systemdCache, err := common.GetSystemdCache()
	if err != nil {
		return fmt.Errorf("get systemd cache: %w", err)
	}
	k.systemdCache = systemdCache
	return nil
}

func (k *SystemdResolver) Close() error {
	k.systemdCache.Close()
	return nil
}

func (k *SystemdResolver) Instantiate(gadgetCtx operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	enableSystemdParam := params.Get(localmanager.Systemd)
	if enableSystemdParam != nil && !enableSystemdParam.AsBool() {
		return nil, nil
	}
	return &SystemdResolverInstance{
		gadgetCtx:      gadgetCtx,
		manager:        k,
		gadgetInstance: gadgetInstance,
	}, nil
}

type SystemdResolverInstance struct {
	gadgetCtx      operators.GadgetContext
	manager        *SystemdResolver
	gadgetInstance any
}

func (m *SystemdResolverInstance) Name() string {
	return OperatorInstanceName
}

func (m *SystemdResolverInstance) PreGadgetRun() error {
	m.manager.systemdCache.Start()
	return nil
}

func (m *SystemdResolverInstance) PostGadgetRun() error {
	m.manager.systemdCache.Stop()
	return nil
}

func (m *SystemdResolverInstance) enrich(ev any) {
	cgroupId := ev.(SystemdResolverInterface).GetCgroupID()
	name, ok := m.manager.systemdCache.GetSystemdUnit(cgroupId)
	if ok {
		ev.(SystemdResolverInterface).SetSystemdName(name)
	}
}

func (m *SystemdResolverInstance) EnrichEvent(ev any) error {
	m.enrich(ev)
	return nil
}

func init() {
	operators.Register(&SystemdResolver{})
}
