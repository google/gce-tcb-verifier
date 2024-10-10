// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fakeovmf

import (
	"fmt"

	"github.com/google/gce-tcb-verifier/ovmf/abi"
	"github.com/google/uuid"
)

const (
	tdxMetadataAddr = 0x100
)

func defaultTdxMetadata() *abi.TDXMetadata {
	return &abi.TDXMetadata{
		Header: &abi.TDXMetadataDescriptor{
			Signature:    abi.TDXMetadataDescriptorMagic,
			Length:       208,
			Version:      abi.TDXMetadataVersion,
			SectionCount: 6,
		},
		Sections: []*abi.TDXMetadataSection{
			{
				DataOffset:  0x20000,
				DataSize:    0x1e0000,
				MemoryBase:  0xffe20000,
				MemorySize:  0x1e0000,
				SectionType: abi.TDXMetadataSectionTypeBFV,
				Attributes:  1,
			},
			{
				DataSize:    0x20000,
				MemoryBase:  0xffe00000,
				MemorySize:  0x20000,
				SectionType: abi.TDXMetadataSectionTypeCFV,
			},
			{
				MemoryBase:  0x810000,
				MemorySize:  0x10000,
				SectionType: abi.TDXMetadataSectionTypeTempMem,
			},
			{
				MemoryBase:  0x80b000,
				MemorySize:  0x2000,
				SectionType: abi.TDXMetadataSectionTypeTempMem,
			},
			{
				MemoryBase:  0x809000,
				MemorySize:  0x2000,
				SectionType: abi.TDXMetadataSectionTypeTDHOB,
			},
			{
				MemoryBase:  0x800000,
				MemorySize:  0x6000,
				SectionType: abi.TDXMetadataSectionTypeTempMem,
			},
		},
	}
}

func initializeOvmfTdxMetadata(firmware []byte, baseOffsetFromEnd int, metadataOffset int, tdxMetadata *abi.TDXMetadata) error {
	offsetFromEnd := baseOffsetFromEnd + abi.SizeofMetadataOffset
	if len(firmware) == 0 || len(firmware) < offsetFromEnd {
		return fmt.Errorf("the given firmware is too small to hold an OVMF metadata offset ending at baseOffsetFromEnd. buffer size: %d, OVMF metadata offset size: %d",
			len(firmware), abi.SizeofMetadataOffset)
	}
	if err := abi.PutUUID(firmware[metadataOffset:], uuid.MustParse(abi.TDXMetadataGUID)); err != nil {
		return err
	}
	if err := tdxMetadata.Put(firmware[metadataOffset+16:]); err != nil {
		return err
	}

	// We generate the GUID-ed table entry and set it to point to the SEV
	// Metadata with an offset calculated from the back.
	guidTableOffset := abi.MetadataOffset{Offset: uint32(len(firmware) - metadataOffset - 16)}
	guidTableOffset.GUIDEntry.GUID = uuid.MustParse(abi.TDXMetadataOffsetGUID)
	guidTableOffset.GUIDEntry.Size = abi.SizeofMetadataOffset
	return guidTableOffset.Put(firmware[len(firmware)-offsetFromEnd:])
}

// InitializeTdxGUIDTableFns creates a TDX GUID table containing the TDXMetadata to test helper
// functions that search for and extract the TDXMetadata from `firmware`. `baseOffsetFromEnd` is the
// offset from the end of the firmware where the footer GUID block will be initialized.
func InitializeTdxGUIDTableFns(firmware []byte, tdxMetadataOffset int, tdxMetadata *abi.TDXMetadata) []func(uint16) error {
	return []func(uint16) error{func(offset uint16) error {
		return initializeOvmfTdxMetadata(firmware, int(offset), tdxMetadataOffset, tdxMetadata)
	}}
}
