// Copyright 2025 The Inspektor Gadget authors
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

// Package symbolizer parses ELF programs and resolves stack addresses to
// symbol names.
package symbolizer

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"syscall"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

var ErrNoSymbols = errors.New("no symbols found")

type Symbolizer struct {
	lock         sync.RWMutex
	symbolTables map[string]*symbolTable // exeKey -> symbolTable
}

type symbol struct {
	Name        string
	Value, Size uint64
}

// symbolTable is a cache of symbols for a specific executable.
type symbolTable struct {
	// symbols is a slice of symbols. Order is preserved for binary search.
	symbols []*symbol
}

func NewSymbolizer() (*Symbolizer, error) {
	s := &Symbolizer{
		symbolTables: make(map[string]*symbolTable),
	}
	return s, nil
}

func GenKey(ino uint64, mtimeSec int64, mtimeNsec uint32) string {
	return fmt.Sprintf("%d-%d-%d", ino, mtimeSec, mtimeNsec)
}

func NewSymbolTable(pid uint32, expectedExeKey string) (*symbolTable, error) {
	var symbols []*symbol

	path := fmt.Sprintf("%s/%d/exe", host.HostProcFs, pid)
	file, err := os.Open(path)
	if err != nil {
		// The process might have terminated, or it might be in an unreachable
		// pid namespace. Either way, we can't resolve symbols.
		return nil, fmt.Errorf("opening process executable: %w", err)
	}
	defer file.Close()
	fs, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat process executable: %w", err)
	}
	stat, ok := fs.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("getting syscall.Stat_t failed")
	}
	ino := stat.Ino
	newKey := GenKey(ino, stat.Mtim.Sec, uint32(stat.Mtim.Nsec))
	if newKey != expectedExeKey {
		return nil, fmt.Errorf("exe key mismatch: expected %s, got %s", expectedExeKey, newKey)
	}

	elfFile, err := elf.NewFile(file)
	if err != nil {
		return nil, fmt.Errorf("parsing ELF file: %w", err)
	}
	defer elfFile.Close()

	symtab, err := elfFile.Symbols()
	if err != nil {
		// No symbols found. This is not an error.
		return &symbolTable{}, nil
	}

	for _, sym := range symtab {
		if sym.Name == "" {
			continue
		}
		if sym.Size == 0 {
			continue
		}
		symbols = append(symbols, &symbol{
			Name:  sym.Name,
			Value: sym.Value,
			Size:  sym.Size,
		})
	}
	slices.SortFunc(symbols, func(a, b *symbol) int {
		if a.Value < b.Value {
			return -1
		}
		if a.Value > b.Value {
			return 1
		}
		return 0
	})
	for i := 0; i < len(symbols)-2; i++ {
		if symbols[i].Value+symbols[i].Size > symbols[i+1].Value {
			// Binary search will not work if symbols overlap.
			return nil, fmt.Errorf("overlapping symbols: %+v and %+v", symbols[i], symbols[i+1])
		}
	}

	return &symbolTable{
		symbols: symbols,
	}, nil
}

// lookupByAddr returns the symbol name for the given address.
func (e *symbolTable) lookupByAddr(address uint64) string {
	// Similar to a trivial binary search, but each symbol is a range.
	n, found := slices.BinarySearchFunc(e.symbols, address, func(a *symbol, b uint64) int {
		if a.Value <= b && a.Value+a.Size > b {
			return 0
		}
		if a.Value > b {
			return 1
		}
		if a.Value < b {
			return -1
		}
		return 0
	})
	if found {
		return e.symbols[n].Name
	}
	return "[unknown]"
}

func (s *Symbolizer) Resolve(pid uint32, exeKey string, addresses []uint64) ([]string, error) {
	res := make([]string, len(addresses))

	if len(addresses) == 0 {
		return res, nil
	}

	s.lock.RLock()
	table, ok := s.symbolTables[exeKey]
	if ok {
		for idx, addr := range addresses {
			res[idx] = table.lookupByAddr(addr)
		}
		s.lock.RUnlock()
		return res, nil
	}
	s.lock.RUnlock()

	var err error
	table, err = NewSymbolTable(pid, exeKey)
	if err != nil {
		return nil, fmt.Errorf("creating new symbolTable: %w", err)
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	s.symbolTables[exeKey] = table
	for idx, addr := range addresses {
		res[idx] = table.lookupByAddr(addr)
	}
	return res, nil
}
