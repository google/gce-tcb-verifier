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

// Package ovmf includes tools for parsing OVMF binaries for measurement-specific values.
package ovmf

import (
	"fmt"

	"github.com/google/gce-tcb-verifier/ovmf/abi"
	"github.com/google/uuid"
)

// GetFwGUIDTable returns OVMF's embedded GUID table.
// GUIDed table must end with a footer block. So it will search for the footer
// first, and if the footer is found, it will use the GUIDed table size written
// in the footer to calculate the beginning and end offset for the GUIDed table
// and return a string view containing the entire GUIDed table except for the
// GUID footer block. If the footer is not found, it will return an error.
func GetFwGUIDTable(firmware []byte) ([]byte, error) {
	guidBlockOffsetFromEnd := abi.FwGUIDTableEndOffset + abi.SizeofFwGUIDEntry
	if len(firmware) < guidBlockOffsetFromEnd {
		return nil, fmt.Errorf("firmware is too small: found size 0x%x < 0x%x", len(firmware),
			guidBlockOffsetFromEnd)
	}

	firmwareGUIDentry := firmware[len(firmware)-guidBlockOffsetFromEnd:]
	guidEntry := new(abi.FwGUIDEntry)
	guidEntry.PopulateFromBytes(firmwareGUIDentry)

	guidBlockGUID := uuid.MustParse(abi.FwGUIDTableFooterGUID)

	// The last entry should be GUIDed Table Footer GUID.
	if guidEntry.GUID != guidBlockGUID {
		// Return error as the GUIDed table is not found.
		return nil, fmt.Errorf("invalid firmware image without the GUIDed table. Got %v, want %v (from %v)",
			guidEntry.GUID.String(), abi.FwGUIDTableFooterGUID, firmwareGUIDentry)
	}

	if (guidEntry.Size < abi.SizeofFwGUIDEntry) || (len(firmware) < int(guidEntry.Size)+abi.FwGUIDTableEndOffset) {
		// GUIDed Table Size has to be larger than FwGUIDEntry struct
		// or there is something seriously wrong with the GUIDed table
		// structure.
		return nil, fmt.Errorf("invalid GUIDed table size: found size %d fw_size: %d", guidEntry.Size,
			len(firmware))
	}

	// Now that we know there is a table, return the table excluding the footer.
	tableContentsLength := int(guidEntry.Size) - abi.SizeofFwGUIDEntry
	tableStartOffset := len(firmware) - abi.FwGUIDTableEndOffset - int(guidEntry.Size)
	return firmware[tableStartOffset : tableStartOffset+tableContentsLength], nil
}

// GetFwGUIDToBlockMap returns a map of GUID to the slice of firmware it represents.
func GetFwGUIDToBlockMap(firmware []byte) (map[string][]byte, error) {
	// Get the GUIDed table without the footer.
	guidTable, err := GetFwGUIDTable(firmware)
	if err != nil {
		return nil, err
	}

	guidTableUnprocessedLength := len(guidTable)
	guidBlockMap := make(map[string][]byte)

	// Traverese upwards from the bottom to populate GUID block map.
	for guidTableUnprocessedLength > 0 {
		// Error out in case the fwGUIDEntry size overflows the table.
		if guidTableUnprocessedLength < abi.SizeofFwGUIDEntry {
			return nil, fmt.Errorf("GUIDed table size unexpected, min exp size: %d remaining size: %d table length: %d",
				abi.SizeofFwGUIDEntry, guidTableUnprocessedLength, len(guidTable))
		}

		entryPos := guidTableUnprocessedLength - abi.SizeofFwGUIDEntry
		guidEntry := new(abi.FwGUIDEntry)
		guidEntry.PopulateFromBytes(guidTable[entryPos : entryPos+abi.SizeofFwGUIDEntry])
		guidEntrySize := int(guidEntry.Size)

		// Error out in case the current guid block size overflows the table
		// or underflows the minimum size.
		if (guidTableUnprocessedLength < guidEntrySize) ||
			(guidEntry.Size < abi.SizeofFwGUIDEntry) {
			return nil, fmt.Errorf("GUIDed table entries are corrupted, remaining size: %d, size found: %d, table length: %d",
				guidTableUnprocessedLength, guidEntry.Size, len(guidTable))
		}

		efiGUID := guidEntry.GUID.String()

		blockStartOffset := guidTableUnprocessedLength - guidEntrySize

		if _, ok := guidBlockMap[efiGUID]; ok {
			return nil, fmt.Errorf("duplicate GUIDs in the table, repeated GUID: %s", efiGUID)
		}
		guidBlockMap[efiGUID] = guidTable[blockStartOffset : blockStartOffset+guidEntrySize]

		guidTableUnprocessedLength -= int(guidEntry.Size)
	}

	return guidBlockMap, nil
}
