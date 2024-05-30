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

// Package secureopen is a small wrapper around
// github.com/cyphar/filepath-securejoin that provides a way to securely open a
// path with O_PATH and checking that the path didn't move outside of the root.
package secureopen

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/cyphar/filepath-securejoin"
)

// SecureOpenOPath joins the two given path components and opens the resulting
// path with O_PATH. SecureOpenOPath gives the following guarantees:
//
// - the resulting path is guaranteed to be scoped inside the provided root
//   path
//
// - the resulting path is guaranteed to be a regular file (not directory,
//   socket, pipe, device, etc.)
func SecureOpenOPath(root, unsafePath string) (*os.File, error) {
	path, err := securejoin.SecureJoin(root, unsafePath)
	if err != nil {
		return nil, fmt.Errorf("resolving path inside rootfs: %w", err)
	}

	fh, err := os.OpenFile(path, unix.O_PATH, 0)
	if err != nil {
		return nil, fmt.Errorf("open o_path procfd: %w", err)
	}
	defer fh.Close()

	procfd := "/proc/self/fd/" + strconv.Itoa(int(fh.Fd()))
	realpath, err := os.Readlink(procfd)
	if err != nil {
		return nil, fmt.Errorf("procfd verification: %w", err)
	}
	if path != realpath {
		return nil, fmt.Errorf("possibly malicious path detected -- refusing to operate on %s", realpath)
	}
	fi, err := fh.Stat()
	if err != nil {
		return nil, fmt.Errorf("procfd stat: %w", err)
	}
	mode := fi.Mode()
	if !mode.IsRegular() {
		return nil, fmt.Errorf("procfd stat: not a regular file -- refusing to operate on file type %q", mode.String()[0])
	}
	fd, err := unix.Dup(int(fh.Fd()))
	if err != nil {
		return nil, fmt.Errorf("procfd dup: %w", err)
	}
	file := os.NewFile(uintptr(fd), realpath)
	return file, nil
}

// SecureReadFile reads the named file and returns the contents.
//
// This is similar to os.ReadFile() except the file is opened with
// SecureOpenOPath().
func SecureReadFile(root, unsafePath string) ([]byte, error) {
	fh, err := SecureOpenOPath(root, unsafePath)
	if err != nil {
		return nil, fmt.Errorf("secureopen: %w", err)
	}
	defer fh.Close()
	procfd := "/proc/self/fd/" + strconv.Itoa(int(fh.Fd()))
	return os.ReadFile(procfd)
}

// SecureOpen opens the named file for reading.
//
// This is similar to os.Open() except the file is opened with
// SecureOpenOPath().
func SecureOpen(root, unsafePath string) (*os.File, error) {
	fh, err := SecureOpenOPath(root, unsafePath)
	if err != nil {
		return nil, fmt.Errorf("secureopen: %w", err)
	}
	defer fh.Close()
	procfd := "/proc/self/fd/" + strconv.Itoa(int(fh.Fd()))
	return os.Open(procfd)
}

// SecureOpenFile is the generalized open call.
//
// This is similar to os.OpenFile() except the file is opened with
// SecureOpenOPath().
func SecureOpenFile(root, unsafePath string, flag int, perm os.FileMode) (*os.File, error) {
	fh, err := SecureOpenOPath(root, unsafePath)
	if err != nil {
		return nil, fmt.Errorf("secureopen: %w", err)
	}
	defer fh.Close()
	procfd := "/proc/self/fd/" + strconv.Itoa(int(fh.Fd()))
	return os.OpenFile(procfd, flag, perm)
}
