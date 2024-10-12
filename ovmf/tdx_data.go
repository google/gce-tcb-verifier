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
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/exp/slices"

	"github.com/google/gce-tcb-verifier/ovmf/abi"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	gib                                              = 1024 * 1024 * 1024
	tdhobBaseAttributes abi.EFIResourceAttributeType = abi.EFIResourceAttributePresent |
		abi.EFIResourceAttributeInitialized |
		abi.EFIResourceAttributeTested
)

func extractTDXMetadata(firmware []byte) (*abi.TDXMetadata, error) {
	guidBlockMap, err := GetFwGUIDToBlockMap(firmware)
	if err != nil {
		return nil, fmt.Errorf("failed to get GUID block map from OVMF: %v", err)
	}
	block, ok := guidBlockMap[abi.TDXMetadataOffsetGUID]
	if !ok {
		return nil, fmt.Errorf("TDX metadata offset GUID block not found: %s", abi.TDXMetadataOffsetGUID)
	}
	if len(block) < 4+abi.SizeofFwGUIDEntry {
		return nil, fmt.Errorf("TDX metadata offset GUID block size too small %d", len(block))
	}
	metadataOffset := binary.LittleEndian.Uint32(block)
	const efiGUIDsize = 16
	maxSize := uint32(len(firmware) - efiGUIDsize)
	if (metadataOffset > maxSize) || (metadataOffset < abi.SizeofTDXMetadataDescriptor) {
		return nil, fmt.Errorf("unexpected TDX metadata offset 0x%x, min size 0x%x, max size 0x%x",
			metadataOffset, abi.SizeofTDXMetadataDescriptor, maxSize)
	}
	var metadataEFIGUID [16]byte
	abi.PutUUID(metadataEFIGUID[:], uuid.MustParse(abi.TDXMetadataGUID))

	metadataGUIDoffset := uint32(len(firmware)) - metadataOffset - efiGUIDsize
	gotMetadataGUID := firmware[metadataGUIDoffset : metadataGUIDoffset+16]
	if !bytes.Equal(metadataEFIGUID[:], gotMetadataGUID) {
		return nil, fmt.Errorf("TDX metadata GUID mismatch. Got %v want %v", gotMetadataGUID, metadataEFIGUID[:])
	}
	// The metadata descriptor is immediately followed by the metadata sections.
	metadataDescriptor := firmware[metadataGUIDoffset+efiGUIDsize:]
	rawMetadata, err := abi.TDXMetadataFromBytes(metadataDescriptor)
	if err != nil {
		return nil, err
	}
	if err := validateTDXMetadataSections(uint32(len(firmware)), rawMetadata); err != nil {
		return nil, err
	}
	return rawMetadata, nil
}

func validateTDXMetadataSections(firmwareLen uint32, rawMetadata *abi.TDXMetadata) error {
	if rawMetadata.Header.Signature != abi.TDXMetadataDescriptorMagic {
		return fmt.Errorf("TDX metadata descriptor signature mismatch. Got 0x%x want 0x%x",
			rawMetadata.Header.Signature, abi.TDXMetadataDescriptorMagic)
	}
	if rawMetadata.Header.Version != abi.TDXMetadataVersion {
		return fmt.Errorf("TDX metadata descriptor version mismatch. Got 0x%x want 0x%x",
			rawMetadata.Header.Version, abi.TDXMetadataVersion)
	}
	expectedLength := abi.SizeofTDXMetadataDescriptor + abi.SizeofTDXMetdataSection*rawMetadata.Header.SectionCount
	if rawMetadata.Header.Length != expectedLength {
		return fmt.Errorf("TDX metadata descriptor length mismatch. Got 0x%x want 0x%x",
			rawMetadata.Header.Length, expectedLength)
	}
	var foundTDHOB, foundBFV bool
	var fvSize uint32
	cfvCheck := func(section *abi.TDXMetadataSection) error {
		if (section.DataOffset > firmwareLen) || (section.DataSize == 0) ||
			((firmwareLen - section.DataOffset) < section.DataSize) {
			return fmt.Errorf("invalid image offset/raw data size, offset: 0x%x, size: 0x%x, firmware size: 0x%x",
				section.DataOffset, section.DataSize, firmwareLen)
		}
		if section.MemorySize != uint64(section.DataSize) {
			return fmt.Errorf("memory size: 0x%x mismatch with raw data size: 0x%x",
				section.MemorySize, section.DataSize)
		}
		fvSize += section.DataSize
		return nil
	}
	for _, section := range rawMetadata.Sections {
		switch section.SectionType {
		case abi.TDXMetadataSectionTypeBFV:
			foundBFV = true
			if err := cfvCheck(section); err != nil {
				return err
			}
		case abi.TDXMetadataSectionTypeCFV:
			if err := cfvCheck(section); err != nil {
				return err
			}
		case abi.TDXMetadataSectionTypeTDHOB:
			if foundTDHOB {
				return fmt.Errorf("TDX metadata contains multiple TD HOB sections")
			}
			foundTDHOB = true
		case abi.TDXMetadataSectionTypeTempMem: // do nothing
		default:
			return fmt.Errorf("unsupported metadata section type: %v", section.SectionType)
		}
	}
	if !foundTDHOB {
		return fmt.Errorf("TDX metadata doesn't contain section for Trust Domain Handover Block (TD HOB)")
	}
	if !foundBFV {
		return fmt.Errorf("TDX metadata doesn't contain section for boot firmware volume")
	}
	if fvSize != firmwareLen {
		return fmt.Errorf("total size of FVs doesn't add up to the fw size, total: 0x%x, expected: 0x%x", fvSize, firmwareLen)
	}

	return nil
}

type tdxFwParser struct {
	Regions            []*MaterialGuestPhysicalRegion
	Sections           []*abi.TDXMetadataSection
	TDHOBregion        *MaterialGuestPhysicalRegion
	DisableEarlyAccept bool
	// MeasureAllRegions forces all regions to be measured, even if they are not marked as
	// extendable in the metadata. This is only to be compatible with earlier versions
	// Google's hypervisor.
	MeasureAllRegions bool
}

func (p *tdxFwParser) validateMetadataSectionGpr(sectionType uint32, gpr GuestPhysicalRegion) error {
	for _, region := range p.Regions {
		if region.GPR.intersect(gpr).Length != 0 {
			return fmt.Errorf("TDX metadata section overlapping with other section. "+
				"Type %v, Start, size [%v, %v] collides with Start, size [%v, %v]",
				sectionType, gpr.Start, gpr.Length, region.GPR.Start, region.GPR.Length)
		}
	}
	return nil
}

func (p *tdxFwParser) parse(firmware []byte, guestRAMbanks []GuestPhysicalRegion) ([]*MaterialGuestPhysicalRegion, error) {
	metadata, err := extractTDXMetadata(firmware)
	if err != nil {
		return nil, err
	}
	var tdHOBregionIndex *wrapperspb.Int32Value
	var privateResources []GuestPhysicalRegion
	for index, section := range metadata.Sections {
		gprSize := section.MemorySize
		gpr := GuestPhysicalRegion{Start: section.MemoryBase, Length: gprSize}
		attributes := section.Attributes
		if p.MeasureAllRegions {
			attributes |= abi.TDXMetadataAttributeExtendMR
		}
		privateResources = append(privateResources, gpr)
		if err := p.validateMetadataSectionGpr(section.SectionType, gpr); err != nil {
			return nil, err
		}
		zeroExtend := func() {
			var buf []byte
			if p.MeasureAllRegions {
				buf = make([]byte, gprSize)
			}
			p.Regions = append(p.Regions, &MaterialGuestPhysicalRegion{
				GPR:            gpr,
				HostBuffer:     buf,
				TDVFAttributes: attributes,
			})
		}
		fvExtend := func() {
			p.Regions = append(p.Regions, &MaterialGuestPhysicalRegion{
				GPR:            gpr,
				HostBuffer:     firmware[section.DataOffset : section.DataOffset+uint32(gprSize)],
				TDVFAttributes: attributes,
			})
		}
		switch section.SectionType {
		case abi.TDXMetadataSectionTypeTDHOB:
			tdHOBregionIndex = &wrapperspb.Int32Value{Value: int32(index)}
			zeroExtend()
		case abi.TDXMetadataSectionTypeTempMem:
			zeroExtend()
		case abi.TDXMetadataSectionTypeBFV:
			fvExtend()
		case abi.TDXMetadataSectionTypeCFV:
			fvExtend()
		default:
			return nil, fmt.Errorf("unsupported metadata section type: %v", section.SectionType)
		}
	}

	if tdHOBregionIndex == nil {
		return nil, fmt.Errorf("TDX metadata sections don't contain section for TD HOB")
	}
	// Don't copy the region since we need to update the buffer within the list.
	p.TDHOBregion = p.Regions[tdHOBregionIndex.Value]
	unacceptedResources := unacceptedMemRanges(privateResources, guestRAMbanks)
	err = p.getTDHOBList(privateResources, unacceptedResources)
	return p.Regions, err
}

func sortedGPRsCopy(a []GuestPhysicalRegion) []GuestPhysicalRegion {
	b := make([]GuestPhysicalRegion, len(a))
	copy(b, a)
	slices.SortFunc(b, gprCmp)
	return b
}

// It's assumed that each slice contains non-overlapping ranges.
func unacceptedMemRanges(privateResources []GuestPhysicalRegion, ramResources []GuestPhysicalRegion) []GuestPhysicalRegion {
	var unacceptedResources []GuestPhysicalRegion
	// Sort the private and ram resources, but don't affect the input arrays since the order matters
	// in getTDHOBList.
	privateResources = sortedGPRsCopy(privateResources)
	ramResources = sortedGPRsCopy(ramResources)
	privIndex := 0
	// A range of memory is unaccepted if is in ramResources and it is not private.
	for _, ramResource := range ramResources {
		var privateRegion GuestPhysicalRegion
		if ramResource.Length == 0 {
			continue
		}
		// privIndex does not have to start back at 0 since the sorting means all previous regions are
		// non-overlapping: forall k < privIndex, privateResources[k].end() <= ramResource.Start.
		for privIndex < len(privateResources) {
			privateRegion = privateResources[privIndex]
			if privateRegion.Length == 0 {
				privIndex++
				continue
			}
			// Skip the private regions which end before the current ram resource.
			if privateRegion.end() <= ramResource.Start {
				privIndex++
				continue
			}
			// Need to move to the next ram resource for finding the overlap if any.
			if privateRegion.Start >= ramResource.end() {
				break
			}
			// The parts of ramResource which are _not_ in this intersection are unaccepted.
			intersection := ramResource.intersect(privateRegion)
			// Add the part of ram resource before intersection to the unaccepted resources.
			if intersection.Start > ramResource.Start {
				intersectingRange := gprRange(ramResource.Start, intersection.Start)
				if intersectingRange.Length != 0 {
					unacceptedResources = append(unacceptedResources, intersectingRange)
				}
			}
			// Shrink the current bank to start after the intersection.
			ramResource.Length = uint64(ramResource.end() - intersection.end())
			ramResource.Start = intersection.end()

			// Move on to the next ram resource if current ram resource is exhausted.
			if ramResource.Length == 0 {
				break
			}

			// Still continue with the same private resource in case there is overlap with multiple ram resources.
		}
		// Push back the remaining the ramResource after overlap (if any) to unaccepted resources.
		if ramResource.Length != 0 {
			unacceptedResources = append(unacceptedResources, ramResource)
		}
	}
	return unacceptedResources
}

func appendTDHobResource(resourceType abi.EFIResourceType,
	resourceAttributes abi.EFIResourceAttributeType,
	gpr GuestPhysicalRegion,
	buf io.Writer) {
	resource := abi.EFIHOBResourceDescriptor{
		Header: abi.EFIHOBGenericHeader{
			HobType:   abi.EFIHOBTypeResourceDescriptor,
			HobLength: abi.SizeofEFIHOBResourceDescriptor,
		},
		Owner:             abi.EFIGUID{},
		ResourceType:      resourceType,
		ResourceAttribute: resourceAttributes,
		PhysicalStart:     gpr.Start,
		ResourceLength:    gpr.Length,
	}
	resource.WriteTo(buf)
}

func (p *tdxFwParser) getTDHOBList(privateResources []GuestPhysicalRegion, unacceptedResources []GuestPhysicalRegion) error {
	numResourceDescriptors := len(unacceptedResources) + len(privateResources)
	hobSize := uint32(abi.SizeofEFIHOBResourceDescriptor * numResourceDescriptors)
	endOfHOBlistOffset := abi.SizeOfEFIHOBHandoffInfoTable + hobSize
	tdHOBbuf := bytes.NewBuffer(nil)
	gpr := p.TDHOBregion.GPR
	tdHOBbuf.Grow(int(gpr.Length))

	handoffInfo := abi.EFIHOBHandoffInfoTable{
		Header: abi.EFIHOBGenericHeader{
			HobType:   abi.EFIHOBTypeHandoff,
			HobLength: abi.SizeOfEFIHOBHandoffInfoTable,
		},
		Version:             abi.EFIHOBHandoffTableVersion,
		BootMode:            abi.BootWithFullConfiguration,
		EfiMemoryTop:        0,
		EfiMemoryBottom:     0,
		EfiFreeMemoryTop:    0,
		EfiFreeMemoryBottom: 0,
		EfiEndOfHobList:     gpr.Start + abi.EFIPhysicalAddress(endOfHOBlistOffset),
	}
	handoffInfo.WriteTo(tdHOBbuf)

	// Memory resource attributes as per section 7.2.1 of
	// https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-virtual-firmware-design-guide-rev-1.01.pdf
	// Note that ENCRYPTED Attributes is omitted by TDX Qemu as per:
	// https://github.com/intel/qemu-tdx/blob/tdx/hw/i386/tdvf-hob.h#L9
	for _, privateGpr := range privateResources {
		appendTDHobResource(abi.EFIResourceSystemMemory, tdhobBaseAttributes,
			privateGpr, tdHOBbuf)
	}

	for _, unacceptedGpr := range unacceptedResources {
		unacceptedResourceAttributes := tdhobBaseAttributes
		// It is guaranteed that there will be an unaccepted region ending before
		// 4 GB as the Uefi binary region ends at 4GB which would be part of already
		// added TDX memory regions.
		if (unacceptedGpr.end() <= 4*gib) || !p.DisableEarlyAccept {
			unacceptedResourceAttributes |= abi.EFIResourceAttributeNeedsEarlyAccept
		}
		appendTDHobResource(abi.EFIResourceMemoryUnaccepted,
			unacceptedResourceAttributes, unacceptedGpr,
			tdHOBbuf)
	}

	endOfList := abi.EFIHOBGenericHeader{
		HobType:   abi.EFIHOBTypeEndOfHOBList,
		HobLength: abi.SizeofHOBGenericHeader,
	}
	endOfList.WriteTo(tdHOBbuf)

	if uint64(tdHOBbuf.Len()) > gpr.Length {
		return fmt.Errorf("TD HOB buffer is overflowing GPR length, max length: 0x%x, actual length: 0x%x", gpr.Length, tdHOBbuf.Len())
	}

	// Resize tdhob_buffer to span the whole of TD HOB range.
	tdHOBbuf.Write(make([]byte, int(gpr.Length)-tdHOBbuf.Len()))

	p.TDHOBregion.HostBuffer = tdHOBbuf.Bytes()
	return nil
}

// ExtractMaterialGuestPhysicalRegionsNoUnacceptedMemory extracts the TDX guest physical regions from
// the firmware binary with the direction that all memory will be accepted early in the firmware.
func ExtractMaterialGuestPhysicalRegionsNoUnacceptedMemory(firmware []byte, guestRAMbanks []GuestPhysicalRegion) ([]*MaterialGuestPhysicalRegion, error) {
	return (&tdxFwParser{MeasureAllRegions: true}).parse(firmware, guestRAMbanks)
}

// ExtractMaterialGuestPhysicalRegionsTDHOBBug extracts the TDX guest physical regions from the
// firmware binary with the direction that the firmware provide some unaccepted memory to the guest
// OS as *not* marked for acceptance by the firmware. All TDVF Metadata sections are measured to
// account for a Google hypervisor bug.
func ExtractMaterialGuestPhysicalRegionsTDHOBBug(firmware []byte, guestRAMbanks []GuestPhysicalRegion) ([]*MaterialGuestPhysicalRegion, error) {
	return (&tdxFwParser{DisableEarlyAccept: true, MeasureAllRegions: true}).parse(
		firmware, guestRAMbanks)
}

// ExtractMaterialGuestPhysicalRegions extracts the TDX guest physical regions from the firmware binary
// with the direction that the firmware provide some unaccepted memory to the guest OS as *not*
// marked for acceptance by the firmware.
func ExtractMaterialGuestPhysicalRegions(firmware []byte) ([]*MaterialGuestPhysicalRegion, error) {
	return (&tdxFwParser{DisableEarlyAccept: true}).parse(firmware, nil)
}
