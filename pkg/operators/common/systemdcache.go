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

package common

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/cgroups"
)

type SystemdSubInterface interface {
	AddCgroup(string, uint64)
	RemoveCgroup(string, uint64)
}

type SystemdCache struct {
	dbusConn *dbus.Conn

	idToUnitname sync.Map

	subscribers []SystemdSubInterface
	subMutex    sync.Mutex

	exit           chan struct{}
	ticker         *time.Ticker
	tickerDuration time.Duration

	useCount      int
	useCountMutex sync.Mutex
}

var (
	systemdCache *SystemdCache
	systemdOnce  sync.Once
)

func GetSystemdCache() (*SystemdCache, error) {
	systemdOnce.Do(func() {
		systemdCache, err = newSystemdCache(1 * time.Second)
	})
	return systemdCache, err
}

func (cache *SystemdCache) Subscribe(sub SystemdSubInterface, publishOldEntries bool) {
	logrus.Debugf("Subscribing to systemd cache")
	cache.subMutex.Lock()
	cache.subscribers = append(cache.subscribers, sub)
	cache.subMutex.Unlock()

	// Publish old entries after subscribing
	// This ensures that the subscriber always has all entries that it needs
	// It may recieve some entries twice because of that
	if publishOldEntries {
		cache.idToUnitname.Range(func(key, value interface{}) bool {
			sub.AddCgroup(value.(string), key.(uint64))
			return true
		})
	}
}

func (cache *SystemdCache) Unsubscribe(sub SystemdSubInterface) {
	cache.subMutex.Lock()
	defer cache.subMutex.Unlock()
	for i, s := range cache.subscribers {
		if s == sub {
			cache.subscribers = append(cache.subscribers[:i], cache.subscribers[i+1:]...)
			return
		}
	}
}

func newSystemdCache(tickerDuration time.Duration) (*SystemdCache, error) {
	dbusConn, err := dbus.NewSystemConnectionContext(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("creating dbus connection: %w", err)
	}

	return &SystemdCache{
		dbusConn:       dbusConn,
		tickerDuration: tickerDuration,
	}, nil
}

func (cache *SystemdCache) loop() {
	for {
		select {
		case <-cache.exit:
			return
		case <-cache.ticker.C:
			cache.update()
		}
	}
}

func (cache *SystemdCache) Close() {
	if cache.exit != nil {
		close(cache.exit)
		cache.exit = nil
	}
	if cache.ticker != nil {
		cache.ticker.Stop()
		cache.ticker = nil
	}
}

func (cache *SystemdCache) Start() {
	cache.useCountMutex.Lock()
	defer cache.useCountMutex.Unlock()

	// No uses before us, we are the first one
	if cache.useCount == 0 {
		cache.update()
		cache.exit = make(chan struct{})
		cache.ticker = time.NewTicker(cache.tickerDuration)
		go cache.loop()
	}
	cache.useCount++
}

func (cache *SystemdCache) Stop() {
	cache.useCountMutex.Lock()
	defer cache.useCountMutex.Unlock()

	// We are the last user, stop everything
	if cache.useCount == 1 {
		cache.Close()
	}
	cache.useCount--
}

func (cache *SystemdCache) publishAdd(unitName string, id uint64) {
	cache.subMutex.Lock()
	defer cache.subMutex.Unlock()
	for _, updater := range cache.subscribers {
		updater.AddCgroup(unitName, id)
	}
}

func (cache *SystemdCache) publishRemove(unitName string, id uint64) {
	cache.subMutex.Lock()
	defer cache.subMutex.Unlock()
	for _, updater := range cache.subscribers {
		updater.RemoveCgroup(unitName, id)
	}
}

func (cache *SystemdCache) update() {
	units, err := cache.dbusConn.ListUnitsByPatternsContext(context.TODO(), []string{"active"}, []string{})
	if err != nil {
		logrus.Debugf("listing systemd units: %s", err)
		return
	}

	// Add new CgroupIDs
	currCgroupIDs := make(map[uint64]interface{})
	for _, unit := range units {
		cgPath, err := cache.dbusConn.GetServicePropertyContext(context.TODO(), unit.Name, "ControlGroup")
		if err != nil {
			continue
		}
		path := cgPath.Value.Value().(string)
		if path == "" {
			continue
		}
		fullpath, err := cgroups.CgroupPathV2AddMountpoint(path)
		if err != nil {
			continue
		}
		id, err := cgroups.GetCgroupID(fullpath)
		if err != nil {
			continue
		}
		name, loaded := cache.GetSystemdUnit(id)
		if !loaded || name != unit.Name {
			cache.idToUnitname.Store(id, unit.Name)
		}
		if !loaded {
			cache.publishAdd(unit.Name, id)
		}
		currCgroupIDs[id] = nil
	}

	// Remove old CgroupIDs
	cache.idToUnitname.Range(func(key, value interface{}) bool {
		id := key.(uint64)
		_, found := currCgroupIDs[id]
		if !found {
			cache.idToUnitname.Delete(id)
			cache.publishRemove(value.(string), id)
		}
		return true
	})
}

func (cache *SystemdCache) GetSystemdUnit(fd uint64) (string, bool) {
	name, loaded := cache.idToUnitname.Load(fd)
	if !loaded {
		return "", false
	}
	return name.(string), true
}
