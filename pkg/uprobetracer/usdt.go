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

package uprobetracer

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	sdtNoteSectionName = ".note.stapsdt"
	sdtBaseSectionName = ".stapsdt.base"
)

type noteHeader struct {
	NameSize uint32
	DescSize uint32
	Type     uint32
}

type usdtAttachInfo struct {
	attachAddress    uint64
	semaphoreAddress uint64
}

func vaddr2ElfOffset(f *elf.File, addr uint64) (uint64, error) {
	for _, prog := range f.Progs {
		if prog.Vaddr <= addr && addr < (prog.Vaddr+prog.Memsz) {
			return addr - prog.Vaddr + prog.Off, nil
		}
	}
	return 0, fmt.Errorf("internal error: elf prog containing addr %x not found", addr)
}

func alignUp[T int | int32 | int64 | uint | uint32 | uint64](n T, align T) T {
	return (n + align - 1) / align * align
}

func getUsdtInfo(filepath string, attachSymbol string) (*usdtAttachInfo, error) {
	parts := strings.Split(attachSymbol, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid USDT section name: %q", attachSymbol)
	}
	providerName := parts[0]
	probeName := parts[1]

	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("opening file %q: %w", filepath, err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stating file %q: %w", filepath, err)
	}
	if !fileInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("ELF file %q is not regular", filepath)
	}

	elfReader, err := elf.NewFile(file)
	if err != nil {
		return nil, fmt.Errorf("reading elf file %q: %w", filepath, err)
	}
	defer elfReader.Close()

	noteSection := elfReader.Section(sdtNoteSectionName)
	if noteSection == nil {
		return nil, errors.New("USDT note section does not exist")
	}
	notesReader := noteSection.Open()

	baseSection := elfReader.Section(sdtBaseSectionName)
	if baseSection == nil {
		return nil, errors.New("USDT base section does not exist")
	}

	wordSize := 4
	if elfReader.Class == elf.ELFCLASS64 {
		wordSize = 8
	}

	// walk through USDT notes, and match with providerName and probeName
	for {
		// see https://man7.org/linux/man-pages/man5/elf.5.html, `Notes (Nhdr)` section for details
		var header noteHeader
		err = binary.Read(notesReader, elfReader.ByteOrder, &header)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("reading USDT note header: %w", err)
		}

		_, err = notesReader.Seek(int64(alignUp(header.NameSize, 4)), io.SeekCurrent)
		if err != nil {
			return nil, fmt.Errorf("seeking USDT note: %w", err)
		}

		desc := make([]byte, alignUp(uint64(header.DescSize), 4))
		err = binary.Read(notesReader, elfReader.ByteOrder, &desc)
		if err != nil {
			return nil, fmt.Errorf("reading USDT note desc: %w", err)
		}

		elfLocation := elfReader.ByteOrder.Uint64(desc[:wordSize])
		elfBase := elfReader.ByteOrder.Uint64(desc[wordSize : 2*wordSize])
		elfSemaphore := elfReader.ByteOrder.Uint64(desc[2*wordSize : 3*wordSize])

		diff := baseSection.Addr - elfBase
		location, err := vaddr2ElfOffset(elfReader, elfLocation+diff)
		if err != nil {
			return nil, err
		}

		if elfSemaphore != 0 {
			elfSemaphore, err = vaddr2ElfOffset(elfReader, elfSemaphore+diff)
			if err != nil {
				return nil, err
			}
		}

		provider := readStringFromBytes(desc, uint32(3*wordSize))
		probe := readStringFromBytes(desc, uint32(3*wordSize+len(provider)+1))
		if provider == providerName && probe == probeName {
			return &usdtAttachInfo{location, elfSemaphore}, nil
		}
	}
	return nil, errors.New("no matching USDT metadata")
}
