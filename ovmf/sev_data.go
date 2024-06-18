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

package ovmf

import (
	"errors"
	"fmt"
	"sort"

	"github.com/google/gce-tcb-verifier/ovmf/abi"
	opb "github.com/google/gce-tcb-verifier/proto/ovmf"
)

// SevData represents SEV-specific data that is extracted from an OVMF binary.
type SevData struct {
	// Expecting to need SEV-ES data.
	SevEs bool

	// Expecting to need SEV-SNP data.
	SevSnp bool

	// Reset block for SEV-ES. This block is needed when SEV-ES is enabled to
	// initialize Application Processors (APs), as SEV-ES does
	// not allow the INIT-SIPI-SIPI procedure to be emulated by the VMM (CPU state
	// is encrypted).
	sevEsResetBlock *opb.SevEsResetBlock

	// The sections defined by the SEV OVMF Metadata contain information about
	// the GPA and sizes of special memory (CPUID page, secret page, and
	// Hypervisor validated pages). When SEV-SNP is enabled, the guest UEFI
	// requires the VMM to find the addresses of those pages by extracting the
	// Metadata from the UEFI ROM and initialize them.
	snpMetadataSections []abi.SevMetadataSection
}

func extractGUIDBlockFromMap(
	guidBlockMap map[string][]byte, guid string, blockSize uint32) ([]byte, error) {
	entry, ok := guidBlockMap[guid]
	if !ok {
		return nil, fmt.Errorf("no matching block found for GUID: %s", guid)
	}
	// Extract the GUID block from the map.
	if uint32(len(entry)) != blockSize {
		return nil, fmt.Errorf("mismatch with GUID block size, GUID: %s expected %d found: %d", guid, blockSize, len(entry))
	}
	return entry, nil
}

// Extracts the SEV-ES reset block from the given `guidBlockMap`, if present.
func extractSevEsResetBlock(guidBlockMap map[string][]byte) (*opb.SevEsResetBlock, error) {
	guidBlock, err := extractGUIDBlockFromMap(guidBlockMap, abi.SevEsResetBlockGUID,
		abi.SizeofSevEsResetBlock)
	if err != nil {
		return nil, fmt.Errorf("could not extract SEV-ES reset block GUID block: %v", err)
	}
	return abi.SevEsResetBlockFromBytes(guidBlock)
}

// SevSectionTypeToString returns section type names for section type codes.
func SevSectionTypeToString(kind uint32) string {
	switch kind {
	case abi.SevCpuidSection:
		return "OVMF_SECTION_TYPE_CPUID"
	case abi.SevSecretSection:
		return "OVMF_SECTION_TYPE_SNP_SECRETS"
	case abi.SevUnmeasuredSection:
		return "OVMF_SECTION_TYPE_SNP_SEC_MEM"
	case abi.SevSvsmCaaSection:
		return "OVMF_SECTION_TYPE_SVSM_CAA"
	default:
		return fmt.Sprintf("[unknown SNP metadata section type: 0x%x]", kind)
	}
}

// Extracts the SEV OVMF Metadata Offset from the given `guidBlockMap`,
// if present.
func extractSevOvmfMetadata(guidBlockMap map[string][]byte, firmware []byte) ([]abi.SevMetadataSection, error) {
	// Extract the GUID table from the firmware.
	guidBlock, err := extractGUIDBlockFromMap(guidBlockMap, abi.SevMetadataOffsetGUID, abi.SizeofMetadataOffset)
	if err != nil {
		return nil, fmt.Errorf("could not extract SEV metadata offset GUID block: %v", err)
	}

	metadataOffset, err := abi.MetadataOffsetFromBytes(guidBlock)
	if err != nil {
		return nil, fmt.Errorf("could not extract SEV metadata offset: %v", err)
	}
	offset := int(metadataOffset.Offset)
	if len(firmware) < offset {
		return nil, fmt.Errorf("firmware is too small: found size %d < %d", len(firmware), offset)
	}
	sevMetadata := abi.SevMetadataFromBytes(firmware[len(firmware)-offset:])

	if sevMetadata.Signature != abi.SevSnpMetadataSignature {
		return nil, fmt.Errorf("the signature of the SEV memory offset is incorrect: %v",
			sevMetadata.Signature)
	}

	// The length of each section is expected to be 12, The length of the
	// offset is expected to be 16. Given the fact that we have both "length"
	// and "sections" we can verify those fields against each other
	if sevMetadata.Length != sevMetadata.Sections*abi.SizeofSevMetadataSection+abi.SizeofSevMetadata {
		return nil, fmt.Errorf("mismatch between SEV memory offset length: %d and SEV metadata offset sections count: %d",
			sevMetadata.Length, sevMetadata.Sections)
	}

	if metadataOffset.Offset < sevMetadata.Length {
		return nil, fmt.Errorf(
			"SEV OVMF Metadata Offset is not large enough to contain the metadata: %d < %d",
			metadataOffset.Offset, sevMetadata.Length)
	}

	var metadataSections []abi.SevMetadataSection

	metadataStart := len(firmware) - int(metadataOffset.Offset) + abi.SizeofSevMetadata
	for it := 0; it < int(sevMetadata.Sections); it++ {
		singleBlock := abi.SevMetadataSectionFromBytes(firmware[metadataStart+it*abi.SizeofSevMetadataSection:])

		metadataSections = append(metadataSections,
			abi.SevMetadataSection{Address: singleBlock.Address,
				Length: singleBlock.Length,
				Kind:   singleBlock.Kind})
	}
	return metadataSections, nil
}

// ExtractFromFirmware parses OVMF binary for SEV-specific data. May only call once.
func (d *SevData) ExtractFromFirmware(data []byte) error {
	if !d.SevEs {
		if d.SevSnp {
			return errors.New("cannot use SEV-SNP without SEV-ES")
		}
		return nil
	}
	guidBlockMap, err := GetFwGUIDToBlockMap(data)
	if err != nil {
		return fmt.Errorf("could not get GUID table from firmware: %v", err)
	}

	if d.SevEs {
		if d.sevEsResetBlock != nil {
			return errors.New("SEV-ES Reset block already set")
		}

		resetBlock, err := extractSevEsResetBlock(guidBlockMap)
		if err != nil {
			return fmt.Errorf("could not extract SEV-ES reset block: %v", err)
		}
		d.sevEsResetBlock = resetBlock
	}

	// If SEV-SNP is enabled, we need to also extract the SEV OVMF Metadata from
	// the firmware ROM.
	if d.SevSnp {
		if d.snpMetadataSections != nil {
			return errors.New("SEV OVMF Metadata already set")
		}

		sections, err := extractSevOvmfMetadata(guidBlockMap, data)
		if err != nil {
			return fmt.Errorf("could not extract SEV OVMF Metadata: %v", err)
		}
		d.snpMetadataSections = sections
	}
	return nil
}

// SevEsResetBlock returns the OVMF SEV-ES reset block if it was found, otherwise error.
func (d *SevData) SevEsResetBlock() (*opb.SevEsResetBlock, error) {
	if d.sevEsResetBlock == nil {
		return nil, errors.New("no SEV-ES reset block available")
	}
	return d.sevEsResetBlock, nil
}

// SnpMetadataSections returns the OVMF SEV-SNP metadata sections if there were found, otherwise
// error.
func (d *SevData) SnpMetadataSections() ([]abi.SevMetadataSection, error) {
	if err := d.validateSections(); err != nil {
		return nil, err
	}
	return d.snpMetadataSections, nil
}

func (d *SevData) validateSections() error {
	if d.snpMetadataSections == nil {
		return errors.New("SEV OVMF metadata not found")
	}
	// Check if the Metadata contains all the necessary types. Further
	// validity of the addresses will be checked during UpdateData().
	allocatedTypeAddress := make(map[uint32]uint32)

	// An internal sortable type to check for overlap
	type sectionCheck struct {
		start uint32
		end   uint32
		kind  uint32
	}
	checkData := make([]sectionCheck, len(d.snpMetadataSections))
	for i, section := range d.snpMetadataSections {
		if v, ok := allocatedTypeAddress[section.Kind]; ok {
			// There is only 1 allowed secret section and cpuid section.
			//
			// By convention, there is only 1 allowed cpuid page. 1 cpuid page is not
			// architecturally enforced, but we also control the UEFI that consumes it
			// and know the guest Linux patches that also consume it, so let's keep it
			// tight here as well and fail on >1.
			if section.Kind == abi.SevSecretSection ||
				section.Kind == abi.SevCpuidSection {
				return fmt.Errorf(
					"expected only 1 section of type %s. Previous section at address 0x%x conflicts with extra section at address 0x%x",
					SevSectionTypeToString(section.Kind), v, section.Address)
			}
		}
		allocatedTypeAddress[section.Kind] = section.Address

		if (section.Length%abi.PageSize != 0) || section.Length == 0 {
			return fmt.Errorf(
				"section %s has length that's not a positive multiple of a 4K page size: 0x%x",
				SevSectionTypeToString(section.Kind), section.Length)
		}
		checkData[i] = sectionCheck{
			start: section.Address,
			end:   section.Address + section.Length,
			kind:  section.Kind}
	}

	if _, ok := allocatedTypeAddress[abi.SevUnmeasuredSection]; !ok {
		return errors.New("no proper pre-validated addresses found in the SEV OVMF Metadata")
	}

	if _, ok := allocatedTypeAddress[abi.SevSecretSection]; !ok {
		return errors.New(
			"no secret page address found from the SEV OVMF Metadata")
	}

	if _, ok := allocatedTypeAddress[abi.SevCpuidSection]; !ok {
		return errors.New("no CPUID page address found in the SEV OVMF Metadata")
	}

	// Check that no section overlaps with any other.
	sort.Slice(checkData, func(i, j int) bool {
		return checkData[i].start < checkData[j].start
	})
	for i := 0; i < len(checkData)-1; i++ {
		if checkData[i].end > checkData[i+1].start {
			return fmt.Errorf("SEV section %s: [0x%x-0x%x] overlaps with %s: [0x%x-0x%x]",
				SevSectionTypeToString(checkData[i].kind), checkData[i].start,
				checkData[i].end, SevSectionTypeToString(checkData[i+1].kind),
				checkData[i+1].start, checkData[i+1].end)
		}
	}

	return nil
}

// GetRipAndCsBaseFromSevEsResetBlock returns the value of RIP and CS base from the SEV-ES reset
// block `sevEsResetBlock`. Returns the pair <rip, cs base>.
func GetRipAndCsBaseFromSevEsResetBlock(sevEsResetBlock *opb.SevEsResetBlock) (uint64, uint64, error) {
	RipMask := uint64(0x0000ffff)
	CsBaseMask := uint64(0xffff0000)
	return uint64(sevEsResetBlock.Addr) & RipMask,
		uint64(sevEsResetBlock.Addr) & CsBaseMask, nil

}
