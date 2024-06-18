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
	"testing"

	"github.com/google/gce-tcb-verifier/ovmf/abi"
	"github.com/google/uuid"
)

// InitializeGUIDTable initializes the GUID table with the given block sizes and populateFns.
func InitializeGUIDTable(
	firmware []byte,
	baseOffsetFromEnd int,
	blockSizes []uint16,
	populateFns []func(offset uint16) error) error {
	// If GUID table is used in the firmware, the footer GUID will be
	// `FwGuidTableFooterGuid`. Make sure that the firmware is large
	// enough to have the footer block.
	footerOffsetFromEnd := baseOffsetFromEnd + abi.SizeofFwGUIDEntry
	if len(firmware) < footerOffsetFromEnd {
		return fmt.Errorf("firmware size is too small to copy the footer block")
	}
	if len(blockSizes) != len(populateFns) {
		return fmt.Errorf("blockSizes and populateFns must have the same length")
	}
	var blockSize uint16
	for i, populateFn := range populateFns {
		if err := populateFn(uint16(footerOffsetFromEnd) + blockSize); err != nil {
			return err
		}
		blockSize += blockSizes[i]
	}
	return (&abi.FwGUIDEntry{
		GUID: uuid.MustParse(abi.FwGUIDTableFooterGUID),
		// `footerBlock.size` will be the sum of the footer block and all the other
		// blocks in the GUID table. For this test, an ES reset block and an SNP
		// boot block are included in the GUID table.
		Size: blockSize + abi.SizeofFwGUIDEntry,
	}).Put(firmware[len(firmware)-footerOffsetFromEnd:])
}

// InitializeSevGUIDTable initializes the GUID table with the given reset block address and SNP
// sections.
func InitializeSevGUIDTable(
	firmware []byte,
	baseOffsetFromEnd int,
	resetBlockAddr uint32,
	snpSections []abi.SevMetadataSection) error {
	return InitializeGUIDTable(firmware, baseOffsetFromEnd, []uint16{
		abi.SizeofSevEsResetBlock,
		abi.SizeofMetadataOffset,
	}, InitializeSevGUIDTableFns(firmware, resetBlockAddr, snpSections))
}

// CleanExample returns an example "UEFI" binary that contains expected metadata.
func CleanExample(t testing.TB, size int) []byte {
	t.Helper()
	if size < 0x1000 {
		t.Fatalf("example size must be >= 0x1000")
	}
	firmware := make([]byte, size)
	copy(firmware[0x800:], []byte("LGTMLGTMLGTMLGTM"))
	copy(firmware[0xa00:], []byte("LGTMLGTMLGTMLGTM"))
	tdxmeta := defaultTdxMetadata()
	populateFns := append(
		InitializeSevGUIDTableFns(firmware[:], SevEsAddrVal, DefaultSnpSections()),
		InitializeTdxGUIDTableFns(firmware[:], tdxMetadataAddr, tdxmeta)...)
	InitializeGUIDTable(firmware, abi.FwGUIDTableEndOffset, []uint16{
		abi.SizeofSevEsResetBlock,
		abi.SizeofMetadataOffset,
		abi.SizeofMetadataOffset, // TDX metadata offset block (in reset vector).
	}, populateFns)
	return firmware
}
