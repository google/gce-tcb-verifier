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

// Package abi defines binary interface conversion functions for the OVMF binary format.
package abi

import (
	"bytes"
	"encoding/binary"
	"fmt"

	opb "github.com/google/gce-tcb-verifier/proto/ovmf"
	"github.com/google/uuid"
)

const (
	// SizeofFwGUIDEntry is the ABI size of the FwGUIDEntry type.
	SizeofFwGUIDEntry = 18

	// FwGUIDTableFooterGUID is the GUIDed Table Footer GUID defined at upstream edk2
	// https://github.com/tianocore/edk2/blob/01726b6d23d4c8a870dbd5b96c0b9e3caf38ef3c/OvmfPkg/ResetVector/Ia16/ResetVectorVtf0.asm.
	FwGUIDTableFooterGUID = "96b582de-1fb2-45f7-baea-a366c55a082d"

	// FwGUIDTableEndOffset is the offset from the end of the Firmware ROM to the end of the GUIDed
	// Table structure.
	FwGUIDTableEndOffset = 0x20

	// PageSize is the default size of a page used in OVMF SEV sections
	PageSize = 4096

	// SevEsResetBlockGUID is the SEV-ES Reset Block GUID and GUIDed Table Footer GUID defined at
	// upstream edk2
	// https://github.com/tianocore/edk2/blob/01726b6d23d4c8a870dbd5b96c0b9e3caf38ef3c/OvmfPkg/ResetVector/Ia16/ResetVectorVtf0.asm.
	SevEsResetBlockGUID = "00f771de-1a7e-4fcb-890e-68c77e2fb44e"

	// SevMetadataOffsetGUID is the SEV OVMF Metadata Offset GUID. In the firmware the GUID is
	// "dc886566-984a-4798-A75e-5585a7bf67cc" (notice the single capital letter).
	// This caused errors when using it in the same manner in the code as the GUID
	// tools will translate it to lowercase.
	SevMetadataOffsetGUID = "dc886566-984a-4798-a75e-5585a7bf67cc"

	// SevSnpMetadataSignature is "A" "S" "E" "V". It will get read as "VESA", which in hex maps to
	// 0x56 0x45 0x53 0x41.
	SevSnpMetadataSignature = 0x56455341

	// SevUnmeasuredSection is the OVMF value of the SEV unmeasured section. Can be found here:
	// https://github.com/tianocore/edk2/blob/master/OvmfPkg/ResetVector/X64/OvmfSevMetadata.asm
	SevUnmeasuredSection = uint32(0x1)
	// SevSecretSection is the OVMF value of the SEV secret section. Can be found here:
	// https://github.com/tianocore/edk2/blob/master/OvmfPkg/ResetVector/X64/OvmfSevMetadata.asm
	SevSecretSection = uint32(0x2)
	// SevCpuidSection is the OVMF value of the SEV CPUID section. Can be found here:
	// https://github.com/tianocore/edk2/blob/master/OvmfPkg/ResetVector/X64/OvmfSevMetadata.asm
	SevCpuidSection = uint32(0x3)
	// SevSvsmCaaSection is the OVMF value of the SEV CPUID section. Can be found here:
	// https://github.com/coconut-svsm/edk2/blob/svsm/OvmfPkg/ResetVector/X64/OvmfSevMetadata.asm
	SevSvsmCaaSection = uint32(0x4)
	// SizeofSevEsResetBlock is the ABI size of the packed struct of an SevEsResetBlock.
	SizeofSevEsResetBlock = 22
	// SizeofMetadataOffset is the ABI size of the packed struct of a MetadataOffset.
	SizeofMetadataOffset = 4 + SizeofFwGUIDEntry
	// SizeofSevMetadata is the ABI size of the packed struct of a SevMetadata.
	SizeofSevMetadata = 16
	// SizeofSevMetadataSection is the ABI size of the packed struct of a SevMetadataSection.
	SizeofSevMetadataSection = 12

	// TDXMetadataSectionTypeBFV is a metadata section descriptor for the boot firmware volume.
	TDXMetadataSectionTypeBFV = 0
	// TDXMetadataSectionTypeCFV is a metadata section descriptor for the configuration firmware
	// volume.
	TDXMetadataSectionTypeCFV = 1
	// TDXMetadataSectionTypeTDHOB is a metadata section descriptor for the trust domain handover
	// block that KVM uses to initialize each vCPU.
	TDXMetadataSectionTypeTDHOB = 2
	// TDXMetadataSectionTypeTempMem is a metadata section descriptor for a memory region that is used
	// for temporary memory.
	TDXMetadataSectionTypeTempMem = 3
	// TDXMetadataVersion is the versioning value for the metadata embedded in the firmware about the
	// TDVF.
	TDXMetadataVersion = 1

	// TDXMetadataOffsetGUID contains launch configuration for TDX VMs.
	TDXMetadataOffsetGUID = "e47a6535-984a-4798-865e-4685a7bf8ec2"
	// TDXMetadataGUID as per:
	// https://github.com/tianocore/edk2/blob/master/OvmfPkg/ResetVector/X64/IntelTdxMetadata.asm#L57
	TDXMetadataGUID = "e9eaf9f3-168e-44d5-a8eb-7f4d8738f6ae"
	// SizeofTDXMetadataDescriptor is the byte size of a TDXMetadataDescriptor struct.
	SizeofTDXMetadataDescriptor = 16
	// SizeofTDXMetdataSection is the byte size of a TDXMetdataSection struct.
	SizeofTDXMetdataSection = 32
	// TDXMetadataDescriptorMagic is the magic number for the TDXMetadataDescriptor Signature.
	TDXMetadataDescriptorMagic = 0x46564454 // 'T', 'D', 'V', 'F'

	// Tcg800155PlatformIDEventHobGUID is the GUID for the any SP800155 platform ID event HOB.
	Tcg800155PlatformIDEventHobGUID = "e2c3bc69-615c-4b5b-8e5c-a033a9c25ed6"
)

// FwGUIDEntry is an ABI type found in OVMF binaries for describing a run of data in the binary as
// associated with a given GUID.
type FwGUIDEntry struct {
	Size uint16
	GUID uuid.UUID
}

// EFIGUID is the big-endian-like representation of a GUID in OVMF binaries.
type EFIGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]uint8
}

// Put writes g in its ABI format to the beginning of data.
func (g EFIGUID) Put(data []byte) error {
	if len(data) < 16 {
		return fmt.Errorf("data too small for GUID: %d < 16", len(data))
	}
	binary.LittleEndian.PutUint32(data[0:4], g.Data1)
	binary.LittleEndian.PutUint16(data[4:6], g.Data2)
	binary.LittleEndian.PutUint16(data[6:8], g.Data3)
	copy(data[8:16], g.Data4[:])
	return nil
}

// parseEFIGUID parses an EFI_GUID in little endian into a uuid.UUID.
func parseEFIGUID(data []byte) (EFIGUID, error) {
	if len(data) != 16 {
		return EFIGUID{}, fmt.Errorf("incorrect data size for EFI GUID: %d, want 16", len(data))
	}
	result := EFIGUID{
		Data1: binary.LittleEndian.Uint32(data[0:4]),
		Data2: binary.LittleEndian.Uint16(data[4:6]),
		Data3: binary.LittleEndian.Uint16(data[6:8]),
	}
	copy(result.Data4[:], data[8:16])
	return result, nil
}

func convertEFIGUID(guid EFIGUID) uuid.UUID {
	var result uuid.UUID
	binary.BigEndian.PutUint32(result[0:4], guid.Data1)
	binary.BigEndian.PutUint16(result[4:6], guid.Data2)
	binary.BigEndian.PutUint16(result[6:8], guid.Data3)
	copy(result[8:16], guid.Data4[:])
	return result
}

// FromEFIGUID parses an EFI_GUID in little endian format into a uuid.UUID.
func FromEFIGUID(efiguid []byte) (uuid.UUID, error) {
	guid, err := parseEFIGUID(efiguid)
	if err != nil {
		return uuid.UUID{}, err
	}
	return convertEFIGUID(guid), nil
}

// PutUUID writes a uuid.UUID to binary in EFI_GUID little endian format.
func PutUUID(data []byte, guid uuid.UUID) error {
	if len(data) < 16 {
		return fmt.Errorf("data too small for GUID: %d < 16", len(data))
	}
	binary.LittleEndian.PutUint32(data[0:4], binary.BigEndian.Uint32(guid[0:4]))
	binary.LittleEndian.PutUint16(data[4:6], binary.BigEndian.Uint16(guid[4:6]))
	binary.LittleEndian.PutUint16(data[6:8], binary.BigEndian.Uint16(guid[6:8]))
	copy(data[8:16], guid[8:16])
	return nil
}

// FromUUID converts a uuid.UUID to EFIGUID.
func FromUUID(guid uuid.UUID) EFIGUID {
	var data [16]byte
	PutUUID(data[:], guid)
	result, _ := parseEFIGUID(data[:])
	return result
}

// Put writes f in its ABI format to the beginning of data.
func (f *FwGUIDEntry) Put(data []byte) error {
	if len(data) < SizeofFwGUIDEntry {
		return fmt.Errorf("data too small for FwGUIDEntry: %d < %d", len(data), SizeofFwGUIDEntry)
	}
	binary.LittleEndian.PutUint16(data[0:2], f.Size)
	return PutUUID(data[2:SizeofFwGUIDEntry], f.GUID)
}

// PopulateFromBytes sets f's fields from data by interpreting data as a packed struct FwGUIDEntry.
func (f *FwGUIDEntry) PopulateFromBytes(data []byte) (err error) {
	f.Size = binary.LittleEndian.Uint16(data[0:2])
	f.GUID, err = FromEFIGUID(data[2:SizeofFwGUIDEntry])
	return err
}

// SevMetadataSection is an ABI-specific type for OVMF binaries. A single section containing
// information about a page that the VMM will have to set for the guest.
type SevMetadataSection struct {
	Address uint32
	Length  uint32
	Kind    uint32
}

// Put writes s in its ABI format to the beginning of data.
func (s *SevMetadataSection) Put(data []byte) error {
	if len(data) < SizeofSevMetadataSection {
		return fmt.Errorf("data too small for SEV metadata section: %d < %d", len(data), SizeofSevMetadataSection)
	}
	binary.LittleEndian.PutUint32(data[0:4], s.Address)
	binary.LittleEndian.PutUint32(data[4:8], s.Length)
	binary.LittleEndian.PutUint32(data[8:12], s.Kind)
	return nil
}

// SevMetadataSectionFromBytes returns the structured type interpretation of the ABI format of the
// same type.
func SevMetadataSectionFromBytes(guidBlock []byte) *SevMetadataSection {
	return &SevMetadataSection{
		Address: binary.LittleEndian.Uint32(guidBlock[0:4]),
		Length:  binary.LittleEndian.Uint32(guidBlock[4:8]),
		Kind:    binary.LittleEndian.Uint32(guidBlock[8:12]),
	}
}

// SevMetadata is the ABI type for SEV-SNP enabled UEFI firmware's GUID table information. The
// table should include the GUID table containing the offset to the SNP metadata location. The
// firmware expects the VMM to extract the metadata and initialize three different types of memory
// ranges (pre-validated range, cpuid page and secret page) as specified.
type SevMetadata struct {
	Signature uint32
	Length    uint32
	Version   uint32
	Sections  uint32
}

// Put writes s in its ABI format to the beginning of data.
func (s *SevMetadata) Put(data []byte) error {
	if len(data) < SizeofSevMetadata {
		return fmt.Errorf("data too small for SEV metadata: %d < %d", len(data), SizeofSevMetadata)
	}
	binary.LittleEndian.PutUint32(data[0:4], s.Signature)
	binary.LittleEndian.PutUint32(data[4:8], s.Length)
	binary.LittleEndian.PutUint32(data[8:12], s.Version)
	binary.LittleEndian.PutUint32(data[12:16], s.Sections)
	return nil
}

// SevMetadataFromBytes interprets an OVMF GUID block as SevMetadata.
func SevMetadataFromBytes(guidBlock []byte) *SevMetadata {
	return &SevMetadata{
		Signature: binary.LittleEndian.Uint32(guidBlock[0:4]),
		Length:    binary.LittleEndian.Uint32(guidBlock[4:8]),
		Version:   binary.LittleEndian.Uint32(guidBlock[8:12]),
		Sections:  binary.LittleEndian.Uint32(guidBlock[12:16]),
	}
}

// MetadataOffset represents the offset information in the GUIDed table pointing to the SNP
// metadata.
type MetadataOffset struct {
	Offset    uint32
	GUIDEntry FwGUIDEntry
}

// Put writes s in its ABI format to the beginning of data./
func (s *MetadataOffset) Put(data []byte) error {
	if len(data) < SizeofMetadataOffset {
		return fmt.Errorf("data too small for SEV metadata offset: %d < %d", len(data), SizeofMetadataOffset)
	}
	binary.LittleEndian.PutUint32(data[0:4], s.Offset)
	if err := s.GUIDEntry.Put(data[4:SizeofMetadataOffset]); err != nil {
		return fmt.Errorf("could not write GUIDEntry: %v", err)
	}
	return nil
}

// MetadataOffsetFromBytes interprets an OVMF GUID block as MetadataOffset.
func MetadataOffsetFromBytes(guidBlock []byte) (*MetadataOffset, error) {
	result := &MetadataOffset{
		Offset: binary.LittleEndian.Uint32(guidBlock[0:4]),
	}
	if err := result.GUIDEntry.PopulateFromBytes(guidBlock[4:SizeofMetadataOffset]); err != nil {
		return nil, fmt.Errorf("could not populate GUIDEntry: %v", err)
	}
	return result, nil
}

// SevEsResetBlockFromBytes interprets an SevEsResetBlock's binary format into a Golang struct.
func SevEsResetBlockFromBytes(data []byte) (*opb.SevEsResetBlock, error) {
	if len(data) != SizeofSevEsResetBlock {
		return nil, fmt.Errorf("unexpected SEV-ES reset block size %d, want: %d", len(data), SizeofSevEsResetBlock)
	}
	// SizeofSevEsResetBlock - 6 = 16, so FromEFIGUID cannot error.
	guid, _ := FromEFIGUID(data[6:SizeofSevEsResetBlock])
	result := &opb.SevEsResetBlock{
		Addr: binary.LittleEndian.Uint32(data[0:4]),
		Size: uint32(binary.LittleEndian.Uint16(data[4:6])),
		Guid: guid[:],
	}
	return result, nil
}

// PutSevEsResetBlock marshals s into its ABI format in data.
func PutSevEsResetBlock(data []byte, s *opb.SevEsResetBlock) error {
	if len(data) < SizeofSevEsResetBlock {
		return fmt.Errorf("unexpected SEV-ES reset block size %d < %d", len(data), SizeofSevEsResetBlock)
	}
	binary.LittleEndian.PutUint32(data[0:4], s.Addr)
	binary.LittleEndian.PutUint16(data[4:6], uint16(s.Size))
	sGUID, err := uuid.FromBytes(s.Guid)
	if err != nil {
		return err
	}

	PutUUID(data[6:SizeofSevEsResetBlock], sGUID)
	return nil
}

// TDXMetadataDescriptor is the header for the TDX metadata section.
type TDXMetadataDescriptor struct {
	Signature    uint32 // Ought to be 'T', 'D', 'V', 'F' in little endian
	Length       uint32
	Version      uint32
	SectionCount uint32
}

// TDXMetadataDescriptorFromBytes returns
func TDXMetadataDescriptorFromBytes(data []byte) (*TDXMetadataDescriptor, error) {
	if len(data) < SizeofTDXMetadataDescriptor {
		return nil, fmt.Errorf("data too small for TDX metadata descriptor: %d < %d", len(data), SizeofTDXMetadataDescriptor)
	}
	return &TDXMetadataDescriptor{
		Signature:    binary.LittleEndian.Uint32(data[0:4]),
		Length:       binary.LittleEndian.Uint32(data[4:8]),
		Version:      binary.LittleEndian.Uint32(data[8:12]),
		SectionCount: binary.LittleEndian.Uint32(data[12:16]),
	}, nil
}

// Put writes TDX metadata descriptor to the beginning of data.
func (h *TDXMetadataDescriptor) Put(data []byte) error {
	if len(data) < SizeofTDXMetadataDescriptor {
		return fmt.Errorf("data too small for TDX metadata descriptor: %d < %d", len(data), SizeofTDXMetadataDescriptor)
	}
	binary.LittleEndian.PutUint32(data[0:4], h.Signature)
	binary.LittleEndian.PutUint32(data[4:8], h.Length)
	binary.LittleEndian.PutUint32(data[8:12], h.Version)
	binary.LittleEndian.PutUint32(data[12:16], h.SectionCount)
	return nil
}

// TDXMetadataSection is information the VMM needs in order to configure TDX for the firmware.
type TDXMetadataSection struct {
	DataOffset                 uint32
	DataSize                   uint32
	MemoryBase                 EFIPhysicalAddress
	MemorySize                 uint64
	SectionType                uint32
	MetadataAttributesExtendmr uint32
}

// TDXMetadataSectionFromBytes returns a parsed TDX metadata section from the OVMF GUID block.
func TDXMetadataSectionFromBytes(data []byte) (*TDXMetadataSection, error) {
	if len(data) < SizeofTDXMetdataSection {
		return nil, fmt.Errorf("data too small for TDX metadata section: %d < %d", len(data), SizeofTDXMetdataSection)
	}
	return &TDXMetadataSection{
		DataOffset:                 binary.LittleEndian.Uint32(data[0:4]),
		DataSize:                   binary.LittleEndian.Uint32(data[4:8]),
		MemoryBase:                 EFIPhysicalAddress(binary.LittleEndian.Uint64(data[8:16])),
		MemorySize:                 binary.LittleEndian.Uint64(data[16:24]),
		SectionType:                binary.LittleEndian.Uint32(data[24:28]),
		MetadataAttributesExtendmr: binary.LittleEndian.Uint32(data[28:32]),
	}, nil
}

// Put writes TDX metadata section to the beginning of data.
func (s *TDXMetadataSection) Put(data []byte) error {
	if len(data) < SizeofTDXMetdataSection {
		return fmt.Errorf("data too small for TDX metadata section: %d < %d", len(data), SizeofTDXMetdataSection)
	}
	binary.LittleEndian.PutUint32(data[0:4], s.DataOffset)
	binary.LittleEndian.PutUint32(data[4:8], s.DataSize)
	binary.LittleEndian.PutUint64(data[8:16], uint64(s.MemoryBase))
	binary.LittleEndian.PutUint64(data[16:24], s.MemorySize)
	binary.LittleEndian.PutUint32(data[24:28], s.SectionType)
	binary.LittleEndian.PutUint32(data[28:32], s.MetadataAttributesExtendmr)
	return nil
}

// TDXMetadata contains information the VMM requires to correctly configure the firmware for TDX.
type TDXMetadata struct {
	Header   *TDXMetadataDescriptor
	Sections []*TDXMetadataSection // hdr.section_count
}

// TDXMetadataFromBytes returns the parsed TDX metadata from the OVMF GUID block.
func TDXMetadataFromBytes(data []byte) (*TDXMetadata, error) {
	hdr, err := TDXMetadataDescriptorFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("could not parse TDX metadata descriptor: %v", err)
	}
	expected := hdr.SectionCount * SizeofTDXMetdataSection
	remainder := uint32(len(data) - SizeofTDXMetadataDescriptor)
	if expected > remainder {
		return nil, fmt.Errorf("data too small for expected section count %d: %d < %d",
			hdr.SectionCount, remainder, expected)
	}
	var sections []*TDXMetadataSection
	buf := bytes.NewReader(data[SizeofTDXMetadataDescriptor:])
	for i := uint32(0); i < hdr.SectionCount; i++ {
		var sectionBytes [SizeofTDXMetdataSection]byte
		// Errors are unreachable given the size check above.
		buf.Read(sectionBytes[:])
		section, _ := TDXMetadataSectionFromBytes(sectionBytes[:])
		sections = append(sections, section)
	}
	return &TDXMetadata{Header: hdr, Sections: sections}, nil
}

// Size returns the size of the TDX metadata in bytes.
func (m *TDXMetadata) Size() uint32 {
	return SizeofTDXMetadataDescriptor + m.Header.SectionCount*SizeofTDXMetdataSection
}

// Put writes TDX metadata to the beginning of data.
func (m *TDXMetadata) Put(data []byte) error {
	if m.Header == nil {
		return fmt.Errorf("TDX metadata descriptor is nil")
	}
	if m.Header.SectionCount != uint32(len(m.Sections)) {
		return fmt.Errorf("TDX metadata illformed. SectionsCount: %d but len(Sections): %d",
			m.Header.SectionCount, len(m.Sections))
	}
	byteSize := m.Size()
	if uint32(len(data)) < byteSize {
		return fmt.Errorf("data too small for %d TDX metadata sections: %d < %d", m.Header.SectionCount,
			len(data), byteSize)
	}
	_ = m.Header.Put(data) // Error unreachable given above check.
	for i := uint32(0); i < m.Header.SectionCount; i++ {
		index := SizeofTDXMetadataDescriptor + i*SizeofTDXMetdataSection
		// Error unreachable given above check.
		_ = m.Sections[i].Put(data[index : index+SizeofTDXMetdataSection])
	}
	return nil
}
