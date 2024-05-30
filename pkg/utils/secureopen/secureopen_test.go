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

package secureopen

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecureOpen(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestSecureOpen")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	err = os.MkdirAll(filepath.Join(dir, "testdir01"), 0700)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(dir, "testfile01"), []byte("testfile01"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../", filepath.Join(dir, "testlink_parent")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("testfile01", filepath.Join(dir, "testlink_file_rel")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/testfile01", filepath.Join(dir, "testlink_file_abs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("testdir01", filepath.Join(dir, "testlink_dir_rel")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/testdir01", filepath.Join(dir, "testlink_dir_abs")); err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		root, unsafe string
		expectedErr  error
		expectedPath string
	}{
		{
			root:         dir,
			unsafe:       "none",
			expectedErr:  fmt.Errorf("open o_path procfd"),
			expectedPath: "",
		},
		{
			root:         dir,
			unsafe:       "testfile01",
			expectedErr:  nil,
			expectedPath: filepath.Join(dir, "testfile01"),
		},
		{
			root:         dir,
			unsafe:       "testlink_parent",
			expectedErr:  fmt.Errorf("procfd stat: not a regular file"),
			expectedPath: "",
		},
		{
			root:         dir,
			unsafe:       "testlink_file_rel",
			expectedErr:  nil,
			expectedPath: filepath.Join(dir, "testfile01"),
		},
		{
			root:         dir,
			unsafe:       "testlink_file_abs",
			expectedErr:  nil,
			expectedPath: filepath.Join(dir, "testfile01"),
		},
		{
			root:         dir,
			unsafe:       "testlink_dir_rel",
			expectedErr:  fmt.Errorf("procfd stat: not a regular file"),
			expectedPath: "",
		},
		{
			root:         dir,
			unsafe:       "testlink_dir_abs",
			expectedErr:  fmt.Errorf("procfd stat: not a regular file"),
			expectedPath: "",
		},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("opening %s", testCase.unsafe), func(t *testing.T) {
			file, err := SecureOpenOPath(testCase.root, testCase.unsafe)
			if err != nil {
				defer file.Close()
			}
			if testCase.expectedErr == nil {
				if err != nil {
					t.Errorf("expected no error, found %v", err)
				}
			} else {
				if !strings.HasPrefix(err.Error(), testCase.expectedErr.Error()) {
					t.Errorf("expected error %v, found %v", testCase.expectedErr, err)
				}
			}
			foundName := ""
			if err == nil {
				foundName = file.Name()
			}
			if foundName != testCase.expectedPath {
				t.Errorf("expected path %q, found %q", testCase.expectedPath, foundName)
			}
		})
	}
}
