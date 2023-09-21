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

package cgrouphook

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/s3rj1k/go-fanotify/fanotify"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/cgroups"
)

type CgroupNotifier struct {
	cgroupNotify *fanotify.NotifyFD

	cgroups map[string]uint64 // map[cgroupPath]cgroupID

	// set to true when Runtime is closed
	closed bool
	done   chan bool

	wg sync.WaitGroup
}

func NewCgroupNotifier() (*CgroupNotifier, error) {
	n := &CgroupNotifier{
		done:    make(chan bool),
		cgroups: make(map[string]uint64),
	}

	if err := n.install(); err != nil {
		n.Close()
		return nil, err
	}

	return n, nil
}

func (n *CgroupNotifier) install() error {
	cgroupPath, err := cgroups.CgroupPathV2AddMountpoint(".")

	openFlags := os.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC
	fanotifyFlags := uint(unix.FAN_CLOEXEC | unix.FAN_CLASS_CONTENT | unix.FAN_UNLIMITED_QUEUE | unix.FAN_UNLIMITED_MARKS | unix.FAN_NONBLOCK)
	cgroupNotify, err := fanotify.Initialize(fanotifyFlags, openFlags)
	if err != nil {
		return err
	}

	n.cgroupNotify = cgroupNotify

	if err := cgroupNotify.Mark(unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM, unix.FAN_OPEN_PERM, unix.AT_FDCWD, cgroupPath); err != nil {
		return fmt.Errorf("fanotify FAN_OPEN_PERM marking of %s: %w", cgroupPath, err)
	}

	n.wg.Add(1)
	go n.watchCgroupNotify()

	return nil
}

func (n *CgroupNotifier) watchCgroupNotify() {
	defer n.wg.Done()

	for {
		stop, err := n.watchCgroupIterate()
		if n.closed {
			n.cgroupNotify.File.Close()
			return
		}
		if err != nil {
			log.Errorf("error watching runtime binary: %v\n", err)
		}
		if stop {
			n.cgroupNotify.File.Close()
			return
		}
	}
}

func (n *CgroupNotifier) watchCgroupIterate() (bool, error) {
	// Get the next event from fanotify.
	// Even though the API allows to pass skipPIDs, we cannot use it here
	// because ResponseAllow would not be called.
	data, err := n.cgroupNotify.GetEvent()
	if err != nil {
		return true, err
	}

	// data can be nil if the event received is from a process in skipPIDs.
	// In that case, skip and get the next event.
	if data == nil {
		return false, nil
	}

	// Don't leak the fd received by GetEvent
	defer data.Close()

	if !data.MatchMask(unix.FAN_OPEN_PERM) {
		// This should not happen: FAN_OPEN_PERM is the only mask Marked
		return false, fmt.Errorf("fanotify: unknown event on runc: mask=%d pid=%d", data.Mask, data.Pid)
	}

	// This unblocks the execution
	defer n.cgroupNotify.ResponseAllow(data)

	path, err := data.GetPath()
	if err != nil {
		return false, err
	}

	if filepath.Base(path) != "cgroup.procs" {
		return false, nil
	}

	cgroupPath := filepath.Dir(path)
	id, err := cgroups.GetCgroupID(cgroupPath)
	if err != nil {
		return false, err
	}

	oldid := n.cgroups[cgroupPath]
	if oldid == id {
		return false, nil
	}
	n.cgroups[cgroupPath] = id

	fmt.Printf("fanotify: event on cgroup: path=%s id=0x%x\n", path, id)

	// TODO: detect when the cgroup is deleted.

	// Using FAN_DELETE requires FAN_REPORT_FID, which Linux < 6.6 does not support for cgroup2
	// See:
	// https://lore.kernel.org/lkml/CABWYdi39+TJd1qV3nWs_eYc7XMC0RvxG22ihfq7rzuPaNvn1cQ@mail.gmail.com/T/

	// man 7 cgroups: The cgroup.events file can be monitored with either
	// - inotify(7), which notifies changes as IN_MODIFY
	// - poll(2), which notifies changes by returning the POLLPRI and POLLERR bits in the revents field.

	return false, nil
}

func (n *CgroupNotifier) Close() {
	n.closed = true
	close(n.done)
	if n.cgroupNotify != nil {
		n.cgroupNotify.File.Close()
	}
	n.wg.Wait()
}
