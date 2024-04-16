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

// Package ovmfsev generates test OVMF binary data to test SEV binary parsing.
package ovmfsev

import (
	"fmt"
	"testing"

	"github.com/google/gce-tcb-verifier/ovmf/abi"
	opb "github.com/google/gce-tcb-verifier/proto/ovmf"
	"github.com/google/uuid"
)

const (
	// SevEsAddrVal is the addr value in the SEV-ES reset block for testing.
	SevEsAddrVal = 0xff0000ff

	// SevSnpValidatedStartAddr is a test-only SEV-SNP boot block address entry.
	SevSnpValidatedStartAddr = 0xff001000
	// SevSnpValidatedLength is a test-only length of the validated block of OVMF.
	SevSnpValidatedLength = 0x00001000
	// SevSnpCpuidAddr is a test-only SEV-SNP boot block address entry.
	SevSnpCpuidAddr = 0xff003000
	// SevSnpSecretAddr is a test-only SEV-SNP boot block address entry.
	SevSnpSecretAddr = 0xff004000
)

// SnpValidatedSection returns a SevMetadataSection of type Unmeasured at the given address and the
// given length.
func SnpValidatedSection(address, length uint32) abi.SevMetadataSection {
	return abi.SevMetadataSection{Address: address, Length: length, Kind: abi.SevUnmeasuredSection}
}

// SnpValidatedSectionDefaultLength returns a SevMetadataSection of type Unmeasured at the given
// address and a default length.
func SnpValidatedSectionDefaultLength(address uint32) abi.SevMetadataSection {
	return SnpValidatedSection(address, SevSnpValidatedLength)
}

// SnpValidatedSectionDefault returns a SevMetadataSection of type Unmeasured at a default address
// and a default length.
func SnpValidatedSectionDefault() abi.SevMetadataSection {
	return SnpValidatedSectionDefaultLength(SevSnpValidatedStartAddr)
}

// SnpCpuidSection returns a SevMetadataSection of Cpuid type at the given address.
func SnpCpuidSection(
	address uint32) abi.SevMetadataSection {
	return abi.SevMetadataSection{Address: address, Length: abi.PageSize, Kind: abi.SevCpuidSection}
}

// SnpCpuidSectionDefault returns a SevMetadataSection of Cpuid type at a default address.
func SnpCpuidSectionDefault() abi.SevMetadataSection {
	return SnpCpuidSection(SevSnpCpuidAddr)
}

// SnpSecretSection returns a SevMetadataSection of Secret type at the given address.
func SnpSecretSection(address uint32) abi.SevMetadataSection {
	return abi.SevMetadataSection{
		Address: address,
		Length:  abi.PageSize,
		Kind:    abi.SevSecretSection,
	}
}

// SnpSecretSectionDefault returns a SevMetadataSection of Secret type at a default address.
func SnpSecretSectionDefault() abi.SevMetadataSection {
	return SnpSecretSection(SevSnpSecretAddr)
}

// DefaultSnpSections returns default entries of the 3 expected SEV metadata sections.
func DefaultSnpSections() []abi.SevMetadataSection {
	return []abi.SevMetadataSection{
		SnpValidatedSectionDefault(),
		SnpCpuidSectionDefault(),
		SnpSecretSectionDefault(),
	}
}

// GenerateExpectedSevResetBlock returns a SevEsResetBlock at the given address.
func GenerateExpectedSevResetBlock(resetBlockAddr uint32) *opb.SevEsResetBlock {
	result := &opb.SevEsResetBlock{}
	resetGUID := uuid.MustParse(abi.SevEsResetBlockGUID)
	result.Addr = resetBlockAddr
	result.Size = abi.SizeofSevEsResetBlock
	result.Guid = resetGUID[:]
	return result
}

// GenerateExpectedSevResetBlockDefault returns a SevEsResetBlock at a default address.
func GenerateExpectedSevResetBlockDefault() *opb.SevEsResetBlock {
	return GenerateExpectedSevResetBlock(SevEsAddrVal)
}

// InitializeSevResetBlock creates SevEsResetBlock at the end of the firmware without GUID table
// to test helper functions when searching and extracting the SevEsResetBlock from the firmware.
// `baseOffsetFromEnd` is the offset from the end of the firmware that the SevResetBlock will be
// initialized.
func InitializeSevResetBlock(firmware []byte, baseOffsetFromEnd int, resetBlockAddr uint32) error {
	offsetFromEnd := baseOffsetFromEnd + abi.SizeofSevEsResetBlock
	if len(firmware) < offsetFromEnd {
		return fmt.Errorf("the given `firmware` is too small to hold a SEV-ES reset block ending at `baseOffsetFromEnd`. buffer size: %d, SEV-ES reset block size: %d",
			len(firmware), abi.SizeofSevEsResetBlock)
	}

	return abi.PutSevEsResetBlock(firmware[len(firmware)-offsetFromEnd:], GenerateExpectedSevResetBlock(resetBlockAddr))
}

// InitializeOvmfSevMetadata creates a SevSnpBootBlock and places it within `firmware`. This
// function is used to help test code that operates on the firmware's SevSnpBootBlock.
// `baseOffsetFromEnd` is the offset from the end of `firmware` where the SevSnpBootBlock will be
// initialized.
func InitializeOvmfSevMetadata(firmware []byte,
	baseOffsetFromEnd int,
	snpSections []abi.SevMetadataSection) error {
	offsetFromEnd := baseOffsetFromEnd + abi.SizeofSevMetadataOffset
	if len(firmware) == 0 || len(firmware) < offsetFromEnd {
		return fmt.Errorf("the given firmware is too small to hold an OVMF metadata offset ending at baseOffsetFromEnd. buffer size: %d, OVMF metadata offset size: %d",
			len(firmware), abi.SizeofSevMetadataOffset)
	}
	// The first part of the Metadata block defines the length and size of the
	// whole structure.
	header := abi.SevMetadata{
		Signature: abi.SevSnpMetadataSignature,
		Length:    uint32(len(snpSections)*abi.SizeofSevMetadataSection + abi.SizeofSevMetadata),
		Version:   1,
		Sections:  uint32(len(snpSections)),
	}

	// The OVMF SEV metadata is expected to be present in the firmware binary
	// at an offset that the structure stored in the GUID table will be pointing
	// to. Given the fact that the GUID-ed table is stored at the end of the
	// firmware the simplest solution is to store the SEV Metadata at
	// the beginning (so the offset for memcpy's will be 0, and the offset from
	// the back stored in the GUID-ed table will be firmware.size())
	if len(firmware) < int(header.Length) {
		return fmt.Errorf("the given firmware is smaller than the OVMF Metadata which is expected to hold. buffer size: %d, OVMF metadata size: %d",
			len(firmware), header.Length)
	}
	header.Put(firmware)
	offsetFromStart := abi.SizeofSevMetadata

	// We copy all the sections onto the firmware right after the header.
	for _, section := range snpSections {
		section.Put(firmware[offsetFromStart : offsetFromStart+abi.SizeofSevMetadataSection])
		offsetFromStart += abi.SizeofSevMetadataSection
	}

	// We generate the GUID-ed table entry and set it to point to the SEV
	// Metadata with an offset calculated from the back.
	guidTableOffset := abi.SevMetadataOffset{Offset: uint32(len(firmware))}
	guidTableOffset.GUIDEntry.GUID = uuid.MustParse(abi.SevMetadataOffsetGUID)
	guidTableOffset.GUIDEntry.Size = abi.SizeofSevMetadataOffset
	guidTableOffset.Put(firmware[len(firmware)-offsetFromEnd:])

	return nil
}

// InitializeSevGUIDTable creates a SEV GUID table containing the SevEsResetBlock and
// SevSnpBootBlock to test helper functions that search for and extract the reset block from
// `firmware`. `baseOffsetFromEnd` is the offset from the end of the firmware where the footer GUID
// block will be initialized.
func InitializeSevGUIDTable(
	firmware []byte,
	baseOffsetFromEnd int,
	resetBlockAddr uint32,
	snpSections []abi.SevMetadataSection) error {
	// If GUID table is used in the firmware, the footer GUID will be
	// `FwGuidTableFooterGuid`. Make sure that the firmware is large
	// enough to have the footer block.
	footerOffsetFromEnd := baseOffsetFromEnd + abi.SizeofFwGUIDEntry
	if len(firmware) < footerOffsetFromEnd {
		return fmt.Errorf("firmware size is too small to copy the footer block")
	}
	var footerBlock abi.FwGUIDEntry
	footerBlock.GUID = uuid.MustParse(abi.FwGUIDTableFooterGUID)

	// `footerBlock.size` will be the sum of the footer block and all the other
	// blocks in the GUID table. For this test, an ES reset block and an SNP
	// boot block are included in the GUID table.
	footerBlock.Size = abi.SizeofFwGUIDEntry + abi.SizeofSevEsResetBlock + abi.SizeofSevMetadataOffset

	// Create a new SevEs firmware block with the GUID table.
	// First copy the SevEsResetBlock to just before the GUID table footer block.
	if err := InitializeSevResetBlock(
		firmware, footerOffsetFromEnd, resetBlockAddr); err != nil {
		return err
	}

	resetBlockOffsetFromEnd := footerOffsetFromEnd + abi.SizeofSevEsResetBlock
	if err := InitializeOvmfSevMetadata(
		firmware, resetBlockOffsetFromEnd, snpSections); err != nil {
		return err
	}
	// Just after the SevEsResetBlock, copy the SevEsFooterBlock.
	blockStart := len(firmware) - footerOffsetFromEnd
	return footerBlock.Put(firmware[blockStart : blockStart+abi.SizeofFwGUIDEntry])
}

// MutateSevEsResetBlock calls mutate on the protobuf representation of the SEV-ES reset block from
// within a properly formatted firmware buffer, and mutates the byte reresentation of the firmware
// to the ABI representation of the SEV-ES reset block.
func MutateSevEsResetBlock(firmware []byte, mutate func(*opb.SevEsResetBlock, int) error) error {
	// The firmware is expected to have the following shape:
	//
	// |...|
	// |SEV Metadata|
	// |ES reset block|
	// |Footer FwGUIDEntry|
	// |0x20 (FwGUIDTableEndOffset)|
	//
	// tableContentsLength below is calculated by removing bottom two
	// elements from the GUID table buffer.
	tableContentsLength := len(firmware) - abi.FwGUIDTableEndOffset - abi.SizeofFwGUIDEntry
	resetBlockOffset := tableContentsLength - abi.SizeofSevEsResetBlock
	resetEntry := firmware[resetBlockOffset:tableContentsLength]
	block, err := abi.SevEsResetBlockFromBytes(resetEntry)
	if err != nil {
		return err
	}
	if err := mutate(block, resetBlockOffset); err != nil {
		return err
	}
	return abi.PutSevEsResetBlock(resetEntry, block)
}

// MutateSevMetadataOffsetBlock calls mutate on the internal representation of the SEV-SNP metadata
// offset block from within a properly formatted firmware buffer, and mutates the byte reresentation
// of the firmware to the ABI representation of the SEV-SNP metadata block offset.
func MutateSevMetadataOffsetBlock(firmware []byte, mutate func(*abi.SevMetadataOffset) error) error {
	// The firmware is expected to have the following shape:
	//
	// |...|
	// |SEV Metadata|
	// |ES reset block|
	// |Footer FwGUIDEntry|
	// |0x20 (FwGUIDTableEndOffset)|
	//
	// tableContentsLength below is calculated by removing bottom two
	// elements from the GUID table buffer.
	tableContentsLength := len(firmware) - abi.FwGUIDTableEndOffset - abi.SizeofFwGUIDEntry
	resetBlockOffset := tableContentsLength - abi.SizeofSevEsResetBlock
	metadataOffset := firmware[resetBlockOffset-abi.SizeofSevMetadataOffset : resetBlockOffset]
	block, err := abi.SevMetadataOffsetFromBytes(metadataOffset)
	if err != nil {
		return err
	}
	if err := mutate(block); err != nil {
		return err
	}
	return block.Put(metadataOffset)
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
	if err := InitializeSevGUIDTable(firmware[:], abi.FwGUIDTableEndOffset, SevEsAddrVal, DefaultSnpSections()); err != nil {
		t.Fatalf("fake.InitializeSevGUIDTable() errored unexpectedly: %v", err)
	}
	return firmware
}
