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
	"strings"
	"testing"

	"github.com/google/gce-tcb-verifier/ovmf/abi"
	"github.com/google/uuid"
)

const (
	// Dummy guid for first element from bottom.
	elem1GUID = "12345678-1234-1234-1234-123456789123"

	// Dummy guid for second element from bottom.
	elem2GUID = "23456789-2341-2341-2341-234567891234"

	sizeofFwGUIDElem1 = 64 + abi.SizeofFwGUIDEntry
	sizeofFwGUIDElem2 = 128 + abi.SizeofFwGUIDEntry
	sizeofFwGUIDTable = sizeofFwGUIDElem1 + sizeofFwGUIDElem2
	sizeofFwImg       = sizeofFwGUIDTable + abi.SizeofFwGUIDEntry + abi.FwGUIDTableEndOffset
)

// Dummy structure for element1.
type FwGUIDElem1 struct {
	data      [64]byte
	guidEntry abi.FwGUIDEntry
}

func (f FwGUIDElem1) PopulateBytes(result []byte) {
	copy(result, f.data[:])
	binary.LittleEndian.PutUint16(result[64:66], f.guidEntry.Size)
	abi.PutUUID(result[66:], f.guidEntry.GUID)
}

func (f FwGUIDElem1) ToBytes() []byte {
	result := make([]byte, 64+abi.SizeofFwGUIDEntry)
	f.PopulateBytes(result)
	return result
}

// Dummy structure for element2.
type FwGUIDElem2 struct {
	data      [128]byte
	guidEntry abi.FwGUIDEntry
}

func (f FwGUIDElem2) PopulateBytes(result []byte) {
	copy(result, f.data[:])
	binary.LittleEndian.PutUint16(result[128:130], f.guidEntry.Size)
	abi.PutUUID(result[130:], f.guidEntry.GUID)
}

func (f FwGUIDElem2) ToBytes() []byte {
	result := make([]byte, 128+abi.SizeofFwGUIDEntry)
	f.PopulateBytes(result)
	return result
}

// FwGUIDTable structure used for testcases.
type FwGUIDTable struct {
	elem2 FwGUIDElem2
	elem1 FwGUIDElem1
}

func (f FwGUIDTable) PopulateBytes(result []byte) {
	f.elem2.PopulateBytes(result[:sizeofFwGUIDElem2])
	f.elem1.PopulateBytes(result[sizeofFwGUIDElem2 : sizeofFwGUIDElem2+sizeofFwGUIDElem1])
}

func (f FwGUIDTable) ToBytes() []byte {
	result := make([]byte, sizeofFwGUIDTable)
	f.PopulateBytes(result)
	return result
}

// FwImg structure used for testcases.
type FwImg struct {
	unusedArea  [0x100000]byte // Fake UEFI code
	guidTable   FwGUIDTable
	footer      abi.FwGUIDEntry
	unusedArea2 [abi.FwGUIDTableEndOffset]byte
}

func (f *FwImg) PopulateGUIDTable() {
	footer := &f.footer
	guidTable := &f.guidTable
	elem1 := &guidTable.elem1
	elem2 := &guidTable.elem2

	footer.Size = (sizeofFwGUIDTable + abi.SizeofFwGUIDEntry)
	footer.GUID = uuid.MustParse(abi.FwGUIDTableFooterGUID)

	elem1.guidEntry.Size = sizeofFwGUIDElem1
	elem1.guidEntry.GUID = uuid.MustParse(elem1GUID)
	for i := range elem1.data {
		elem1.data[i] = '1'
	}
	elem2.guidEntry.Size = sizeofFwGUIDElem2
	elem2.guidEntry.GUID = uuid.MustParse(elem2GUID)
	for i := range elem2.data {
		elem2.data[i] = '2'
	}
}

func (f FwImg) ToBytes() []byte {
	result := make([]byte, sizeofFwImg)
	f.guidTable.PopulateBytes(result[:sizeofFwGUIDTable])
	footerSlice := result[sizeofFwGUIDTable : sizeofFwGUIDTable+abi.SizeofFwGUIDEntry]
	binary.LittleEndian.PutUint16(footerSlice[0:2], f.footer.Size)
	abi.PutUUID(footerSlice[2:], f.footer.GUID)
	copy(result[sizeofFwGUIDTable+abi.SizeofFwGUIDEntry:], f.unusedArea[:])
	return result
}

func TestInvalidGuidTableFooter(t *testing.T) {
	var fw FwImg
	fw.PopulateGUIDTable()

	// Corrupt the footer guid.
	var zeros uuid.UUID
	fw.footer.GUID = zeros
	firmware := fw.ToBytes()

	_, err := GetFwGUIDToBlockMap(firmware)
	want := "invalid firmware image without the GUIDed table"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("GetFwGUIDToBlockMap(%v) = _, %v, expected \"%s\"", firmware, err, want)
	}
}

func TestInvalidGuidTableFooterSize(t *testing.T) {
	var fw FwImg
	fw.PopulateGUIDTable()

	// Reduce the table size.
	fw.footer.Size = 0
	firmware := fw.ToBytes()

	want := "invalid GUIDed table size"
	if _, err := GetFwGUIDToBlockMap(firmware); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("GetFwGUIDToBlockMap(%v) = _, %v, expected an error containing \"%s\"", firmware, err, want)
	}
}

func TestInvalidGuidTableSize(t *testing.T) {
	var fw FwImg
	fw.PopulateGUIDTable()

	// Increase the table size.
	fw.footer.Size += sizeofFwImg
	firmware := fw.ToBytes()

	want := "invalid GUIDed table size"
	if _, err := GetFwGUIDToBlockMap(firmware); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("GetFwGUIDToBlockMap(%v) = %v, expected an error containing \"%s\"", firmware, err, want)
	}
}

func TestInvalidFirmwareSize(t *testing.T) {
	var fw FwImg
	fw.PopulateGUIDTable()

	// Pass the smaller firmware size.
	firmware := fw.ToBytes()[0:abi.SizeofFwGUIDEntry]

	want := "firmware is too small"
	if _, err := GetFwGUIDToBlockMap(firmware); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("GetFwGUIDToBlockMap(%v) = %v, expected an error containing \"%s\"", firmware, err, want)
	}
}

func TestCorruptedEntry1GetGuidToBlockMap(t *testing.T) {
	var fw FwImg
	guidTable := &fw.guidTable

	fw.PopulateGUIDTable()

	// Decrease the size of the GUID entry below minimum.
	guidTable.elem1.guidEntry.Size = abi.SizeofFwGUIDEntry - 1

	firmware := fw.ToBytes()

	want := "GUIDed table entries are corrupted"
	if _, err := GetFwGUIDToBlockMap(firmware); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("GetFwGUIDToBlockMap(%v) = %v, expected an error containing \"%s\"", firmware, err, want)
	}
}

func TestCorruptedEntry2GetGuidToBlockMap(t *testing.T) {
	var fw FwImg
	guidTable := &fw.guidTable

	fw.PopulateGUIDTable()

	// Increase the size of the GUID entry to be more than guidTable size.
	guidTable.elem1.guidEntry.Size += sizeofFwGUIDTable

	firmware := fw.ToBytes()

	want := "GUIDed table entries are corrupted"
	if _, err := GetFwGUIDToBlockMap(firmware); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("GetFwGUIDToBlockMap(%v) = %v, expected an error containing \"%s\"", firmware, err, want)
	}
}

func TestUnexpSizeGetGuidToBlockMap(t *testing.T) {
	var fw FwImg
	guidTable := &fw.guidTable

	fw.PopulateGUIDTable()

	// Increase the size of the GUID entry to leave out unexpected remaining
	// table size.
	guidTable.elem1.guidEntry.Size += (sizeofFwGUIDElem2 - 4)

	firmware := fw.ToBytes()

	want := "GUIDed table size unexpected"
	if _, err := GetFwGUIDToBlockMap(firmware); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("GetFwGUIDToBlockMap(%v) = %v, expected an error containing \"%s\"", firmware, err, want)
	}
}

func TestDuplicateGuidsGetGuidToBlockMap(t *testing.T) {
	var fw FwImg
	guidTable := &fw.guidTable

	fw.PopulateGUIDTable()

	// Update the GUID of elem1 to be same as elem2.
	guidTable.elem1.guidEntry.GUID = guidTable.elem2.guidEntry.GUID

	firmware := fw.ToBytes()

	want := "duplicate GUIDs in the table"
	if _, err := GetFwGUIDToBlockMap(firmware); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("GetFwGUIDToBlockMap(%v) = %v, expected an error containing \"%s\"", firmware, err, want)
	}
}

func TestValidGetGuidToBlockMap(t *testing.T) {
	var fw FwImg
	guidTable := &fw.guidTable

	fw.PopulateGUIDTable()

	firmware := fw.ToBytes()

	guidBlockMap, err := GetFwGUIDToBlockMap(firmware)
	if err != nil {
		t.Fatal(err)
	}
	elem1Entry, ok := guidBlockMap[elem1GUID]
	if !ok {
		t.Errorf("GetFwGUIDToBlockMap(%v) = %v, want a table with guid %s", firmware, guidBlockMap, elem1GUID)
	}
	if !bytes.Equal(elem1Entry[:], guidTable.elem1.ToBytes()) {
		t.Errorf("unequal elem1 entries. Got %v, want %v", elem1Entry[:], guidTable.elem1.ToBytes())
	}

	elem2Entry, ok := guidBlockMap[elem2GUID]
	if !ok {
		t.Errorf("GetFwGUIDToBlockMap(%v) = %v, want a table with guid %s", firmware, guidBlockMap, elem2GUID)
	}
	if !bytes.Equal(elem2Entry[:], guidTable.elem2.ToBytes()) {
		t.Errorf("unequal elem1 entries. Got %v, want %v", elem2Entry[:], guidTable.elem2.ToBytes())
	}
}
