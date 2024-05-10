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

package abi

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/uuid"
)

const (
	// SizeOfEFIHOBHandoffInfoTable is the size of the HOB info table ABI representation.
	SizeOfEFIHOBHandoffInfoTable = 56
	// SizeofEFIHOBResourceDescriptor is the size of the HOB resource descriptor ABI representation.
	SizeofEFIHOBResourceDescriptor = 48
	// SizeofHOBGenericHeader is the size of the HOB generic header ABI representation.
	SizeofHOBGenericHeader = 8
	// SizeofHOBGUID is the size of the GUID HOB header prior to associated data.
	SizeofHOBGUID = SizeofHOBGenericHeader + 16
	// MaxGUIDHOBDataSize is the maximum size of an EFI_HOB_GUID_TYPE's associated data.
	MaxGUIDHOBDataSize = 0x1000 - SizeofHOBGUID
)

// EFIResourceType is an enum type for resource descriptors.
type EFIResourceType uint32

const (
	// EFIResourceSystemMemory is the system memory resource type specified in UEFI spec.
	EFIResourceSystemMemory EFIResourceType = 0
	// EFIResourceMemoryUnaccepted is the memory unaccepted resource type specified in UEFI spec.
	EFIResourceMemoryUnaccepted EFIResourceType = 7
)

// EFIResourceAttributeType is an enum type for resource attributes as described in the UEFI
// platform initialization (PI) specification:
// https://uefi.org/sites/default/files/resources/PI_Spec_1_6.pdf
type EFIResourceAttributeType uint32

const (
	// EFIResourceAttributePresent is a physical memory attribute: The memory region exists.
	EFIResourceAttributePresent EFIResourceAttributeType = 1
	// EFIResourceAttributeInitialized is a physical memory attribute: The memory region has been
	// initialized.
	EFIResourceAttributeInitialized EFIResourceAttributeType = 2
	// EFIResourceAttributeTested is a physical memory attribute: The memory region has been
	// tested.
	EFIResourceAttributeTested EFIResourceAttributeType = 4
	// EFIResourceAttributeNeedsEarlyAccept is not in the PI 1.6 spec, but describes a memory region
	// that needs early acceptance into the TEE.
	EFIResourceAttributeNeedsEarlyAccept EFIResourceAttributeType = 0x10000000
)

const (
	// EFIHOBTypeHandoff is a HobType in a generic header for a handoff block.
	EFIHOBTypeHandoff = 1
	// EFIHOBHandoffTableVersion is the version number of the handoff table.
	EFIHOBHandoffTableVersion = 9
	// EFIHOBTypeResourceDescriptor is a HobType in a generic header for a resource descriptor block.
	EFIHOBTypeResourceDescriptor = 3
	// EFIHOBTypeGUIDExtension is a HobType in a generic header for a GUID extension block.
	EFIHOBTypeGUIDExtension = 4
	// EFIHOBTypeEndOfHOBList is a HobType in a generic header for the end of the HOB list.
	EFIHOBTypeEndOfHOBList = 0xFFFF
)

// EFIHOBGenericHeader describes the format and size of the data inside a HOB.
// All HOBs must contain this HOB header.
type EFIHOBGenericHeader struct {
	// HobType identifies the HOB data structure type.
	HobType uint16
	// HobLength is the length in bytes of the HOB.
	HobLength uint16
	// 32 bits of reserved data follow.
}

// WriteTo writes the HOB header to the given writer.
func (h EFIHOBGenericHeader) WriteTo(w io.Writer) (int64, error) {
	reserved := uint32(0)
	if err := binary.Write(w, binary.LittleEndian, h.HobType); err != nil {
		return 0, err
	}
	if err := binary.Write(w, binary.LittleEndian, h.HobLength); err != nil {
		return 0, err
	}
	if err := binary.Write(w, binary.LittleEndian, reserved); err != nil {
		return 0, err
	}
	return SizeofHOBGenericHeader, nil
}

// EFIBootMode describes the system boot mode as determined during the HOB producer phase.
type EFIBootMode uint32

// EFIPhysicalAddress presents a physical address where data may go.
type EFIPhysicalAddress uint64

// EFIHOBHandoffInfoTable is a data structure from EDK2.
type EFIHOBHandoffInfoTable struct {
	// Header is a generic header such that Header.HobType = EFIHOBTypeHandoff
	Header EFIHOBGenericHeader // 8 bytes
	// Version is the version number pertaining to the PHIT HOB definition.
	// This value is four bytes in length to provide an 8-byte aligned entry when it is combined with
	// the 4-byte BootMode.
	Version uint32
	// BootMode is the system boot mode as determined during the HOB producer phase.
	BootMode EFIBootMode
	// EfiMemoryTop is the highest address location of memory that is allocated for use by the HOB
	// producer phase. This address must be 4-KB aligned to meet page restrictions of UEFI.
	EfiMemoryTop EFIPhysicalAddress
	// EfiMemoryBottom is the lowest address location of memory that is allocated for use by the HOB
	// producer phase.
	EfiMemoryBottom EFIPhysicalAddress
	// EfiFreeMemoryTop is the highest address location of free memory that is currently available
	// for use by the HOB producer phase.
	EfiFreeMemoryTop EFIPhysicalAddress
	// EfiFreeMemoryBottom is the lowest address location of free memory that is available for use by
	// the HOB producer phase.
	EfiFreeMemoryBottom EFIPhysicalAddress
	// EfiEndOfHobList is the address of the end of the HOB list.
	EfiEndOfHobList EFIPhysicalAddress
}

// WriteTo writes the HOB info table to the given writer.
func (t EFIHOBHandoffInfoTable) WriteTo(w io.Writer) (int64, error) {
	if _, err := t.Header.WriteTo(w); err != nil {
		return 0, err
	}
	if err := binary.Write(w, binary.LittleEndian, t.Version); err != nil {
		return 0, err
	}
	if err := binary.Write(w, binary.LittleEndian, t.BootMode); err != nil {
		return 0, err
	}
	if err := binary.Write(w, binary.LittleEndian, t.EfiMemoryTop); err != nil {
		return 0, err
	}
	if err := binary.Write(w, binary.LittleEndian, t.EfiMemoryBottom); err != nil {
		return 0, err
	}
	if err := binary.Write(w, binary.LittleEndian, t.EfiFreeMemoryTop); err != nil {
		return 0, err
	}
	if err := binary.Write(w, binary.LittleEndian, t.EfiFreeMemoryBottom); err != nil {
		return 0, err
	}
	if err := binary.Write(w, binary.LittleEndian, t.EfiEndOfHobList); err != nil {
		return 0, err
	}
	return SizeOfEFIHOBHandoffInfoTable, nil
}

// EFIHOBResourceDescriptor describes the resource properties of all fixed, non-relocatable resource
// ranges found on the processor host bus during the HOB producer phase.
type EFIHOBResourceDescriptor struct {
	// Header is a generic header with Header.HobType = EFI_HOB_TYPE_RESOURCE_DESCRIPTOR.
	Header EFIHOBGenericHeader
	// Owner is a GUID representing the owner of the resource. This GUID is used by HOB consumer phase
	// components to correlate device ownership of a resource.
	Owner EFIGUID
	// ResourceType is this HOB's resource type.
	ResourceType EFIResourceType
	// ResourceAttribute describes this HOB's resource attributes.
	ResourceAttribute EFIResourceAttributeType
	// PhysicalStart is the physical start address of the resource region.
	PhysicalStart EFIPhysicalAddress
	// ResourceLength is the number of bytes of the resource region.
	ResourceLength uint64
}

// WriteTo writes the HOB resource descriptor to the given writer.
func (d EFIHOBResourceDescriptor) WriteTo(w io.Writer) (int64, error) {
	var owner [16]byte
	d.Owner.Put(owner[:])

	if _, err := d.Header.WriteTo(w); err != nil {
		return 0, err
	}
	if _, err := w.Write(owner[:]); err != nil {
		return 0, err
	}
	if err := binary.Write(w, binary.LittleEndian, d.ResourceType); err != nil {
		return 0, err
	}
	if err := binary.Write(w, binary.LittleEndian, d.ResourceAttribute); err != nil {
		return 0, err
	}
	if err := binary.Write(w, binary.LittleEndian, d.PhysicalStart); err != nil {
		return 0, err
	}
	if err := binary.Write(w, binary.LittleEndian, d.ResourceLength); err != nil {
		return 0, err
	}
	return SizeofEFIHOBResourceDescriptor, nil
}

// EFIHOBGUID is for an EFI_HOB_TYPE_GUID_EXTENSION for named unstructured data associated with a
// given GUID.
type EFIHOBGUID struct {
	Header EFIHOBGenericHeader
	GUID   EFIGUID
	Data   []byte
}

func sizedWrite(w io.Writer, data []byte, want int) (int, error) {
	n, err := w.Write(data)
	if err != nil {
		return n, err
	}
	if n != want {
		return n, fmt.Errorf("write truncated to %d, expected %d", n, want)
	}
	return n, nil
}

type writeToable interface {
	WriteTo(io.Writer) (int64, error)
}

func sizedWriteTo(a writeToable, w io.Writer, want int64) (int64, error) {
	n, err := a.WriteTo(w)
	if err != nil {
		return n, err
	}
	if n != want {
		return n, fmt.Errorf("write truncated to %d, expected %d", n, want)
	}
	return n, nil
}

// WriteTo writes the HOB GUID to the given writer.
func (h EFIHOBGUID) WriteTo(w io.Writer) (int64, error) {
	if h.Header.HobType != EFIHOBTypeGUIDExtension {
		return 0, fmt.Errorf("invalid HOB type: %d", h.Header.HobType)
	}
	wantLength := SizeofHOBGUID + len(h.Data)
	if int(h.Header.HobLength) != wantLength {
		return 0, fmt.Errorf("invalid HOB length: %d, want %d", h.Header.HobLength, wantLength)
	}
	if n, err := sizedWriteTo(h.Header, w, SizeofHOBGenericHeader); err != nil {
		return n, err
	}
	var guid [16]byte
	h.GUID.Put(guid[:])
	if n, err := sizedWrite(w, guid[:], 16); err != nil {
		return int64(n), err
	}
	if n, err := sizedWrite(w, h.Data, len(h.Data)); err != nil {
		return int64(n), err
	}
	return int64(h.Header.HobLength), nil
}

// CreateEFIHOBGUID returns a correctly constructed EFIHOBGUID for the given GUID'ed data.
func CreateEFIHOBGUID(guid uuid.UUID, data []byte) (EFIHOBGUID, error) {
	dataSize := (len(data) + 0x7) &^ 0x7 // HOBs must be 8-byte-aligned.
	if dataSize != len(data) {
		data = append(data, make([]byte, dataSize-len(data))...)
	}
	if len(data) > MaxGUIDHOBDataSize {
		return EFIHOBGUID{}, fmt.Errorf("data too long: %d > %d", len(data), MaxGUIDHOBDataSize)
	}
	return EFIHOBGUID{
		Header: EFIHOBGenericHeader{
			HobType:   EFIHOBTypeGUIDExtension,
			HobLength: uint16(SizeofHOBGenericHeader + 16 + len(data)),
		},
		GUID: FromUUID(guid),
		Data: data,
	}, nil
}
