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
	"encoding/hex"
	"testing"

	"github.com/google/gce-tcb-verifier/ovmf/abi"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/go-cmp/cmp"
)

func TestValidateTDXMetadataSections(t *testing.T) {
	tests := []struct {
		name        string
		firmwareLen uint32
		rawMetadata *abi.TDXMetadata
		wantErr     string
	}{
		{
			name:        "bad signature",
			rawMetadata: &abi.TDXMetadata{Header: &abi.TDXMetadataDescriptor{Signature: 0xbad}},
			wantErr:     "TDX metadata descriptor signature mismatch. Got 0xbad want 0x46564454",
		},
		{
			name: "bad version",
			rawMetadata: &abi.TDXMetadata{
				Header: &abi.TDXMetadataDescriptor{
					Signature: abi.TDXMetadataDescriptorMagic,
					Version:   0xbad,
				},
			},
			wantErr: "TDX metadata descriptor version mismatch. Got 0xbad want 0x1",
		},
		{
			name: "bad length",
			rawMetadata: &abi.TDXMetadata{
				Header: &abi.TDXMetadataDescriptor{
					Signature:    abi.TDXMetadataDescriptorMagic,
					Version:      abi.TDXMetadataVersion,
					Length:       0xbad,
					SectionCount: 1,
				},
			},
			wantErr: "TDX metadata descriptor length mismatch. Got 0xbad want 0x30",
		},
		{
			name:        "image offset larger than firmwareLen",
			firmwareLen: 0x200000,
			rawMetadata: &abi.TDXMetadata{
				Header: &abi.TDXMetadataDescriptor{
					Signature:    abi.TDXMetadataDescriptorMagic,
					Version:      abi.TDXMetadataVersion,
					Length:       0x30,
					SectionCount: 1,
				},
				Sections: []*abi.TDXMetadataSection{
					{
						SectionType: abi.TDXMetadataSectionTypeBFV,
						DataOffset:  0xc0000000,
						DataSize:    1,
					},
				},
			},
			wantErr: "invalid image offset/raw data size, offset: 0xc0000000, size: 0x1, firmware size: 0x200000",
		},
		{
			name:        "image size zero",
			firmwareLen: 0x200000,
			rawMetadata: &abi.TDXMetadata{
				Header: &abi.TDXMetadataDescriptor{
					Signature:    abi.TDXMetadataDescriptorMagic,
					Version:      abi.TDXMetadataVersion,
					Length:       0x30,
					SectionCount: 1,
				},
				Sections: []*abi.TDXMetadataSection{
					{
						SectionType: abi.TDXMetadataSectionTypeBFV,
					},
				},
			},
			wantErr: "invalid image offset/raw data size, offset: 0x0, size: 0x0, firmware size: 0x200000",
		},
		{
			name:        "image offset, size outsize firmwareLen",
			firmwareLen: 0x200000,
			rawMetadata: &abi.TDXMetadata{
				Header: &abi.TDXMetadataDescriptor{
					Signature:    abi.TDXMetadataDescriptorMagic,
					Version:      abi.TDXMetadataVersion,
					Length:       0x30,
					SectionCount: 1,
				},
				Sections: []*abi.TDXMetadataSection{
					{
						SectionType: abi.TDXMetadataSectionTypeCFV,
						DataOffset:  0x1fffff,
						DataSize:    0x100,
					},
				},
			},
			wantErr: "invalid image offset/raw data size, offset: 0x1fffff, size: 0x100, firmware size: 0x200000",
		},
		{
			name:        "memory size mismatch",
			firmwareLen: 0x200000,
			rawMetadata: &abi.TDXMetadata{
				Header: &abi.TDXMetadataDescriptor{
					Signature:    abi.TDXMetadataDescriptorMagic,
					Version:      abi.TDXMetadataVersion,
					Length:       0x30,
					SectionCount: 1,
				},
				Sections: []*abi.TDXMetadataSection{
					{
						SectionType: abi.TDXMetadataSectionTypeBFV,
						DataOffset:  0x1fffff,
						DataSize:    1,
					},
				},
			},
			wantErr: "memory size: 0x0 mismatch with raw data size: 0x1",
		},
		{
			name:        "missing TD HOB",
			firmwareLen: 0x200000,
			rawMetadata: &abi.TDXMetadata{
				Header: &abi.TDXMetadataDescriptor{
					Signature:    abi.TDXMetadataDescriptorMagic,
					Version:      abi.TDXMetadataVersion,
					Length:       0x30,
					SectionCount: 1,
				},
				Sections: []*abi.TDXMetadataSection{
					{
						SectionType: abi.TDXMetadataSectionTypeBFV,
						DataOffset:  0x1fffff,
						DataSize:    1,
						MemorySize:  1,
					},
				},
			},
			wantErr: "TDX metadata doesn't contain section for Trust Domain Handover Block (TD HOB)",
		},
		{
			name:        "multiple TD HOB",
			firmwareLen: 0x200000,
			rawMetadata: &abi.TDXMetadata{
				Header: &abi.TDXMetadataDescriptor{
					Signature:    abi.TDXMetadataDescriptorMagic,
					Version:      abi.TDXMetadataVersion,
					Length:       0x50,
					SectionCount: 2,
				},
				Sections: []*abi.TDXMetadataSection{
					{
						SectionType: abi.TDXMetadataSectionTypeTDHOB,
						DataOffset:  0x1fffff,
						DataSize:    1,
						MemorySize:  1,
					},
					{
						SectionType: abi.TDXMetadataSectionTypeTDHOB,
						DataOffset:  0x1fffff,
						DataSize:    1,
						MemorySize:  1,
					},
				},
			},
			wantErr: "TDX metadata contains multiple TD HOB sections",
		},
		{
			name:        "missing BFV",
			firmwareLen: 0x200000,
			rawMetadata: &abi.TDXMetadata{
				Header: &abi.TDXMetadataDescriptor{
					Signature:    abi.TDXMetadataDescriptorMagic,
					Version:      abi.TDXMetadataVersion,
					Length:       0x50,
					SectionCount: 2,
				},
				Sections: []*abi.TDXMetadataSection{
					{
						SectionType: abi.TDXMetadataSectionTypeTDHOB,
						DataOffset:  0x1fffff,
						DataSize:    1,
						MemorySize:  1,
					},
				},
			},
			wantErr: "TDX metadata doesn't contain section for boot firmware volume",
		},
		{
			name:        "unsupported section type",
			firmwareLen: 0x200000,
			rawMetadata: &abi.TDXMetadata{
				Header: &abi.TDXMetadataDescriptor{
					Signature:    abi.TDXMetadataDescriptorMagic,
					Version:      abi.TDXMetadataVersion,
					Length:       0x30,
					SectionCount: 1,
				},
				Sections: []*abi.TDXMetadataSection{
					{
						SectionType: 123,
						DataOffset:  0x1fffff,
						DataSize:    1,
						MemorySize:  1,
					},
				},
			},
			wantErr: "unsupported metadata section type: 123",
		},
		{
			name:        "firmware length mismatch",
			firmwareLen: 0x200000,
			rawMetadata: &abi.TDXMetadata{
				Header: &abi.TDXMetadataDescriptor{
					Signature:    abi.TDXMetadataDescriptorMagic,
					Version:      abi.TDXMetadataVersion,
					Length:       0x50,
					SectionCount: 2,
				},
				Sections: []*abi.TDXMetadataSection{
					{
						SectionType: abi.TDXMetadataSectionTypeTDHOB,
						DataOffset:  0x1fffff,
						DataSize:    1, // Not a firmware volume, so not counted.
						MemorySize:  1,
					},
					{
						SectionType: abi.TDXMetadataSectionTypeBFV,
						DataOffset:  0x100000,
						DataSize:    0x64,
						MemorySize:  0x64,
					},
				},
			},
			wantErr: "total size of FVs doesn't add up to the fw size, total: 0x64, expected: 0x200000",
		},
		{
			name:        "success",
			firmwareLen: 0x200000,
			rawMetadata: &abi.TDXMetadata{
				Header: &abi.TDXMetadataDescriptor{
					Signature:    abi.TDXMetadataDescriptorMagic,
					Version:      abi.TDXMetadataVersion,
					Length:       0x50,
					SectionCount: 2,
				},
				Sections: []*abi.TDXMetadataSection{
					{
						SectionType: abi.TDXMetadataSectionTypeTDHOB,
						MemoryBase:  0xffe00000,
						MemorySize:  0x1000,
					},
					{
						SectionType: abi.TDXMetadataSectionTypeBFV,
						DataOffset:  0,
						DataSize:    0x200000,
						MemorySize:  0x200000,
					},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateTDXMetadataSections(tc.firmwareLen, tc.rawMetadata); !match.Error(err, tc.wantErr) {
				t.Errorf("validateTDXMetadataSections(%v, %v) returned error: %v, want error: %v", tc.firmwareLen, tc.rawMetadata, err, tc.wantErr)
			}
		})
	}
}

func TestExtractTDXMetadata(t *testing.T) {
	tcs := []struct {
		name     string
		firmware []byte
		want     *abi.TDXMetadata
		wantErr  string
	}{
		{
			name:    "empty",
			wantErr: "failed to get GUID block map from OVMF",
		},
		{
			firmware: []byte{
				18, 0, // size
				// FwGuidTableFooter
				0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d,
				// End padding
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			},
			wantErr: "TDX metadata offset GUID block not found",
		},
		{
			name: "block too small",
			firmware: []byte{
				18, 0, // size of this entry
				// "e47a6535-984a-4798-865e-4685a7bf8ec2"
				0x35, 0x65, 0x7a, 0xe4, 0x4a, 0x98, 0x98, 0x47, 0x86, 0x5e, 0x46, 0x85, 0xa7, 0xbf, 0x8e, 0xc2,
				36, 0, // size of the whole table including the footer
				// FwGuidTableFooter
				0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d,
				// End padding
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			},
			wantErr: "TDX metadata offset GUID block size too small",
		},
		{
			name: "offset too small",
			firmware: []byte{
				0, 0, 0, 0, // Offset
				22, 0, // size of this entry
				// "e47a6535-984a-4798-865e-4685a7bf8ec2"
				0x35, 0x65, 0x7a, 0xe4, 0x4a, 0x98, 0x98, 0x47, 0x86, 0x5e, 0x46, 0x85, 0xa7, 0xbf, 0x8e, 0xc2,
				40, 0, // size of the whole table including the footer
				// FwGuidTableFooter
				0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d,
				// End padding
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			},
			wantErr: "unexpected TDX metadata offset 0x0, min size 0x10, max size 0x38",
		},
		{
			firmware: []byte{
				0x38, 0, 0, 0, // Offset points to the beginning of this input.
				22, 0, // size of this entry
				// "e47a6535-984a-4798-865e-4685a7bf8ec2"
				0x35, 0x65, 0x7a, 0xe4, 0x4a, 0x98, 0x98, 0x47, 0x86, 0x5e, 0x46, 0x85, 0xa7, 0xbf, 0x8e, 0xc2,
				40, 0, // size of the whole table including the footer
				// FwGuidTableFooter
				0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d,
				// End padding
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			},
			wantErr: "TDX metadata GUID mismatch",
		},
		{
			name: "success",
			firmware: []byte{
				// TDX metadata GUID
				0xf3, 0xf9, 0xea, 0xe9, 0x8e, 0x16, 0xd5, 0x44, 0xa8, 0xeb, 0x7f, 0x4d, 0x87, 0x38, 0xf6, 0xae,

				'T', 'D', 'V', 'F', // Signature
				80, 0, 0, 0, // Length
				1, 0, 0, 0, // Version
				2, 0, 0, 0, // Section count
				0, 0, 0, 0, // Data offset
				64, 0, 0, 0, // Data size counts up to this first section
				0, 0, 0, 0, 1, 0, 0, 0, // Memory base
				64, 0, 0, 0, 0, 0, 0, 0, // Memory size
				2, 0, 0, 0, // Section type TD HOB not counted towards the firmware volumes.
				0x51, 0, 0, 0, // Metadata attributes extendmr [end of first section]
				0, 0, 0, 0, // Data offset
				168, 0, 0, 0, // Data size
				0, 0, 0xe0, 0xff, 0, 0, 0, 0, // Memory base
				168, 0, 0, 0, 0, 0, 0, 0, // Memory size
				0, 0, 0, 0, // Section type
				0xcd, 0xab, 0x21, 0x43, // Metadata attributes extendmr

				0x98, 0, 0, 0, // Offset points to the beginning of this input.
				22, 0, // size of this entry
				// "e47a6535-984a-4798-865e-4685a7bf8ec2"
				0x35, 0x65, 0x7a, 0xe4, 0x4a, 0x98, 0x98, 0x47, 0x86, 0x5e, 0x46, 0x85, 0xa7, 0xbf, 0x8e, 0xc2,
				40, 0, // size of the whole table including the footer
				// FwGuidTableFooter
				0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d,
				// End padding
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			},
			want: &abi.TDXMetadata{
				Header: &abi.TDXMetadataDescriptor{
					Signature:    abi.TDXMetadataDescriptorMagic,
					Length:       80,
					Version:      abi.TDXMetadataVersion,
					SectionCount: 2,
				},
				Sections: []*abi.TDXMetadataSection{
					{
						DataOffset:                 0,
						DataSize:                   64,
						MemoryBase:                 0x100000000,
						MemorySize:                 64,
						SectionType:                2,
						MetadataAttributesExtendmr: 0x51,
					},
					{
						DataOffset:                 0,
						DataSize:                   168,
						MemoryBase:                 0xffe00000,
						MemorySize:                 168,
						SectionType:                0,
						MetadataAttributesExtendmr: 0x4321abcd,
					},
				},
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractTDXMetadata(tc.firmware)
			if !match.Error(err, tc.wantErr) {
				t.Fatalf("extractTDXMetadata(%v) returned error %v, want %v", tc.firmware, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("extractTDXMetadata(%v) returned diff (-want +got):\n%s", tc.firmware, diff)
			}
		})
	}
}

func TestValidateMetadataSectionGpr(t *testing.T) {
	tests := []struct {
		name    string
		p       *tdxFwParser
		gpr     GuestPhysicalRegion
		wantErr string
	}{
		{
			name: "add to empty",
			p:    &tdxFwParser{},
			gpr: GuestPhysicalRegion{
				Start:  0,
				Length: 700,
			},
		},
		{
			name: "successful add to non-empty",
			p: &tdxFwParser{
				Regions: []*MaterialGuestPhysicalRegion{
					{
						GPR: GuestPhysicalRegion{
							Start:  0,
							Length: 700,
						},
					},
				},
			},
			gpr: GuestPhysicalRegion{
				Start:  700,
				Length: 700,
			},
		},
		{
			name: "intersects",
			p: &tdxFwParser{
				Regions: []*MaterialGuestPhysicalRegion{
					{
						GPR: GuestPhysicalRegion{
							Start:  0,
							Length: 700,
						},
					},
				},
			},
			gpr: GuestPhysicalRegion{
				Start:  600,
				Length: 400,
			},
			wantErr: "TDX metadata section overlapping with other section. Type 789, Start, size [600, 400] collides with Start, size [0, 700]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.p.validateMetadataSectionGpr(789, tc.gpr); !match.Error(err, tc.wantErr) {
				t.Errorf("%v.validateMetadataSectionGpr(789, %v) returned error: %v, want error: %v", tc.p, tc.gpr, err, tc.wantErr)
			}
		})
	}
}

func TestUnacceptedMemRanges(t *testing.T) {
	tests := []struct {
		name             string
		privateResources []GuestPhysicalRegion
		ramResources     []GuestPhysicalRegion
		want             []GuestPhysicalRegion
	}{
		{
			name: "empty",
		},
		{
			name: "pre-sorted",
			privateResources: []GuestPhysicalRegion{
				{Start: 0, Length: 700},               // skipped
				{Start: 1000, Length: 0},              // skipped
				{Start: 0x3fffff000, Length: 0x2000},  // overlap with ram resource
				{Start: 0x1800000000, Length: 0x1000}, // Past the ram resources
			},
			ramResources: []GuestPhysicalRegion{
				{Start: 0x400000000, Length: 0x400000000},
				{Start: 0x800000000, Length: 0x1000000000}, // not coalesced
			},
			want: []GuestPhysicalRegion{
				{Start: 0x400001000, Length: 0x3fffff000},
				{Start: 0x800000000, Length: 0x1000000000},
			},
		},
		{
			name: "unsorted",
			privateResources: []GuestPhysicalRegion{
				{Start: 0x3fffff000, Length: 0x2000},  // overlap with ram resource
				{Start: 1000, Length: 0},              // skipped
				{Start: 0x1800000000, Length: 0x1000}, // Past the ram resources
				{Start: 0, Length: 700},               // skipped
			},
			ramResources: []GuestPhysicalRegion{
				{Start: 0x800000000, Length: 0x1000000000}, // not coalesced
				{Start: 0x400000000, Length: 0x400000000},
			},
			want: []GuestPhysicalRegion{
				{Start: 0x400001000, Length: 0x3fffff000},
				{Start: 0x800000000, Length: 0x1000000000},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := unacceptedMemRanges(tc.privateResources, tc.ramResources)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("unacceptedMemRanges(%v, %v) returned an unexpected diff (-want +got): %v", tc.privateResources, tc.ramResources, diff)
			}
		})
	}
}

func TestGetTDHOBList(t *testing.T) {
	tcs := []struct {
		name                string
		gpr                 GuestPhysicalRegion
		privateResources    []GuestPhysicalRegion
		unacceptedResources []GuestPhysicalRegion
		disableEarlyAccept  bool
		want                []byte
		wantErr             string
	}{
		{
			name:    "overflow",
			wantErr: "TD HOB buffer is overflowing GPR length, max length: 0x0, actual length: 0x40",
		},
		{
			name: "basic",
			gpr: GuestPhysicalRegion{
				Start:  0x10,
				Length: 0x40,
			},
			want: []byte{1, 0, // Header hob type
				0x38, 0, // Header hob length (56)
				0, 0, 0, 0, // Header reserved
				9, 0, 0, 0, // version
				0, 0, 0, 0, // boot mode
				0, 0, 0, 0, 0, 0, 0, 0, // efi memory top
				0, 0, 0, 0, 0, 0, 0, 0, // efi memory bottom
				0, 0, 0, 0, 0, 0, 0, 0, // efi free memory top
				0, 0, 0, 0, 0, 0, 0, 0, // efi free memory bottom
				0x48, 0, 0, 0, 0, 0, 0, 0, // efi end of hob list (gpr start plus hob size)
				// end of hob list
				0xff, 0xff, 8, 0, 0, 0, 0, 0,
			},
		},
		{
			name: "early accept",
			gpr: GuestPhysicalRegion{
				Start:  0x10,
				Length: 0xd0, // base length plus 3 regions' section sizes (0x90)
			},
			privateResources: []GuestPhysicalRegion{
				{Start: 0x100, Length: 0x1000},
			},
			unacceptedResources: []GuestPhysicalRegion{
				{Start: 0xff000000, Length: 0x1000},
				{Start: 0x400000000, Length: 0x400000000},
			},
			disableEarlyAccept: false,
			want: []byte{1, 0, // Header hob type
				0x38, 0, // Header hob length (56)
				0, 0, 0, 0, // Header reserved
				9, 0, 0, 0, // version
				0, 0, 0, 0, // boot mode
				0, 0, 0, 0, 0, 0, 0, 0, // efi memory top
				0, 0, 0, 0, 0, 0, 0, 0, // efi memory bottom
				0, 0, 0, 0, 0, 0, 0, 0, // efi free memory top
				0, 0, 0, 0, 0, 0, 0, 0, // efi free memory bottom
				0xd8, 0, 0, 0, 0, 0, 0, 0, // efi end of hob list (gpr start plus hob size)
				// private resource
				3, 0, // Header hob type resource descriptor
				0x30, 0, // Header hob length (48)
				0, 0, 0, 0, // Header reserved
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Owner (zeros)
				0, 0, 0, 0, // Resource type system memory (0)
				7, 0, 0, 0, // Resource attribute TD HOB base attributes present, initialized, tested 111b
				0, 1, 0, 0, 0, 0, 0, 0, // Physical start (private resource gpr start)
				0, 0x10, 0, 0, 0, 0, 0, 0, // Resource length (private resource gpr length)
				// unaccepted resource below 4GiB
				3, 0, // Header hob type resource descriptor
				0x30, 0, // Header hob length (48)
				0, 0, 0, 0, // Header reserved
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Owner (zeros)
				7, 0, 0, 0, // Resource type memory unaccepted (7)
				7, 0, 0, 0x10, // Resource attribute TD HOB base attributes present, initialized, tested, needs early acceptance
				0, 0, 0, 0xff, 0, 0, 0, 0, // Physical start (private resource gpr start)
				0, 0x10, 0, 0, 0, 0, 0, 0, // Resource length (private resource gpr length)
				// unaccepted resource above 4GiB
				3, 0, // Header hob type resource descriptor
				0x30, 0, // Header hob length (48)
				0, 0, 0, 0, // Header reserved
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Owner (zeros)
				7, 0, 0, 0, // Resource type memory unaccepted (7)
				7, 0, 0, 0x10, // Resource attribute TD HOB base attributes present, initialized, tested, needs early acceptance
				0, 0, 0, 0, 4, 0, 0, 0, // Physical start (private resource gpr start)
				0, 0, 0, 0, 4, 0, 0, 0, // Resource length (private resource gpr length)
				// end of hob list
				0xff, 0xff, 8, 0, 0, 0, 0, 0,
			},
		},
		{
			name: "no early accept",
			gpr: GuestPhysicalRegion{
				Start:  0x10,
				Length: 0xd0, // base length plus 3 regions' section sizes (0x90)
			},
			privateResources: []GuestPhysicalRegion{
				{Start: 0x100, Length: 0x1000},
			},
			unacceptedResources: []GuestPhysicalRegion{
				{Start: 0xff000000, Length: 0x1000},
				{Start: 0x400000000, Length: 0x400000000},
			},
			disableEarlyAccept: true,
			want: []byte{1, 0, // Header hob type
				0x38, 0, // Header hob length (56)
				0, 0, 0, 0, // Header reserved
				9, 0, 0, 0, // version
				0, 0, 0, 0, // boot mode
				0, 0, 0, 0, 0, 0, 0, 0, // efi memory top
				0, 0, 0, 0, 0, 0, 0, 0, // efi memory bottom
				0, 0, 0, 0, 0, 0, 0, 0, // efi free memory top
				0, 0, 0, 0, 0, 0, 0, 0, // efi free memory bottom
				0xd8, 0, 0, 0, 0, 0, 0, 0, // efi end of hob list (gpr start plus hob size)
				// private resource
				3, 0, // Header hob type resource descriptor
				0x30, 0, // Header hob length (48)
				0, 0, 0, 0, // Header reserved
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Owner (zeros)
				0, 0, 0, 0, // Resource type system memory (0)
				7, 0, 0, 0, // Resource attribute TD HOB base attributes present, initialized, tested 111b
				0, 1, 0, 0, 0, 0, 0, 0, // Physical start (private resource gpr start)
				0, 0x10, 0, 0, 0, 0, 0, 0, // Resource length (private resource gpr length)
				// unaccepted resource below 4GiB
				3, 0, // Header hob type resource descriptor
				0x30, 0, // Header hob length (48)
				0, 0, 0, 0, // Header reserved
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Owner (zeros)
				7, 0, 0, 0, // Resource type memory unaccepted (7)
				7, 0, 0, 0x10, // Resource attribute TD HOB base attributes present, initialized, tested, needs early acceptance
				0, 0, 0, 0xff, 0, 0, 0, 0, // Physical start (private resource gpr start)
				0, 0x10, 0, 0, 0, 0, 0, 0, // Resource length (private resource gpr length)
				// unaccepted resource above 4GiB
				3, 0, // Header hob type resource descriptor
				0x30, 0, // Header hob length (48)
				0, 0, 0, 0, // Header reserved
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Owner (zeros)
				7, 0, 0, 0, // Resource type memory unaccepted (7)
				7, 0, 0, 0, // Resource attribute TD HOB base attributes present, initialized, tested (~needs early acceptance~)
				0, 0, 0, 0, 4, 0, 0, 0, // Physical start (private resource gpr start)
				0, 0, 0, 0, 4, 0, 0, 0, // Resource length (private resource gpr length)
				// end of hob list
				0xff, 0xff, 8, 0, 0, 0, 0, 0,
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			p := &tdxFwParser{
				TDHOBregion: &MaterialGuestPhysicalRegion{
					GPR: tc.gpr,
				},
				DisableEarlyAccept: tc.disableEarlyAccept,
			}
			err := p.getTDHOBList(tc.privateResources, tc.unacceptedResources)
			if !match.Error(err, tc.wantErr) {
				t.Errorf("getTDHOBList(%v, %v, %v) returned error %v, want error %v", tc.gpr, tc.privateResources, tc.unacceptedResources, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			got := p.TDHOBregion.HostBuffer
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("getTDHOBList(%v, %v, %v) returned diff (-want +got): %v", tc.gpr, tc.privateResources, tc.unacceptedResources, diff)
			}
		})
	}
}

func TestTdxFwParserParse(t *testing.T) {
	tcs := []struct {
		name          string
		p             *tdxFwParser
		firmware      []byte
		guestRAMbanks []GuestPhysicalRegion
		want          *tdxFwParser
		wantErr       string
	}{
		{
			name: "empty",
			p:    &tdxFwParser{},
			firmware: []byte{
				// TDX metadata GUID
				0xf3, 0xf9, 0xea, 0xe9, 0x8e, 0x16, 0xd5, 0x44, 0xa8, 0xeb, 0x7f, 0x4d, 0x87, 0x38, 0xf6, 0xae,

				'T', 'D', 'V', 'F', // Signature
				80, 0, 0, 0, // Length
				1, 0, 0, 0, // Version
				2, 0, 0, 0, // Section count

				// TD HOB
				0, 0, 0, 0, // Data offset
				0, 0, 0, 0, // Data size
				0, 0, 0, 0, 1, 0, 0, 0, // Memory base
				0xe0, 0, 0, 0, 0, 0, 0, 0, // Memory size (the TD HOB minimum size is 0xd0, but we go higher)
				2, 0, 0, 0, // Section type TD HOB not counted towards the firmware volumes.
				0x51, 0, 0, 0, // Metadata attributes extendmr [end of first section]

				// BFV
				0, 0, 0, 0, // Data offset
				168, 0, 0, 0, // Data size
				0, 0, 0xe0, 0xff, 0, 0, 0, 0, // Memory base
				168, 0, 0, 0, 0, 0, 0, 0, // Memory size
				0, 0, 0, 0, // Section type
				0xcd, 0xab, 0x21, 0x43, // Metadata attributes extendmr

				// TDX Metadata offset
				0x98, 0, 0, 0, // Offset points to the beginning of this input.
				22, 0, // size of this entry
				// "e47a6535-984a-4798-865e-4685a7bf8ec2"
				0x35, 0x65, 0x7a, 0xe4, 0x4a, 0x98, 0x98, 0x47, 0x86, 0x5e, 0x46, 0x85, 0xa7, 0xbf, 0x8e, 0xc2,
				40, 0, // size of the whole table including the footer
				// FwGuidTableFooter
				0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d,
				// End padding
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			},
			guestRAMbanks: []GuestPhysicalRegion{{Start: 0x100000000, Length: 0xe0}, {Start: 0xffe00000, Length: 168}},
			want: &tdxFwParser{
				Regions: []*MaterialGuestPhysicalRegion{
					{GPR: GuestPhysicalRegion{Start: 0x100000000, Length: 0xe0},
						HostBuffer: []byte{1, 0, // Header hob type
							0x38, 0, // Header hob length (56)
							0, 0, 0, 0, // Header reserved
							9, 0, 0, 0, // version
							0, 0, 0, 0, // boot mode
							0, 0, 0, 0, 0, 0, 0, 0, // efi memory top
							0, 0, 0, 0, 0, 0, 0, 0, // efi memory bottom
							0, 0, 0, 0, 0, 0, 0, 0, // efi free memory top
							0, 0, 0, 0, 0, 0, 0, 0, // efi free memory bottom
							0x98, 0, 0, 0, 1, 0, 0, 0, // efi end of hob list (gpr start plus hob size)
							// private resource above 4GiB
							3, 0, // Header hob type resource descriptor
							0x30, 0, // Header hob length (48)
							0, 0, 0, 0, // Header reserved
							0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Owner (zeros)
							0, 0, 0, 0, // Resource type system memory (0) because early accept disabled
							7, 0, 0, 0, // Resource attribute TD HOB base attributes present, initialized, tested
							0, 0, 0, 0, 1, 0, 0, 0, // Physical start (private resource gpr start)
							0xe0, 0, 0, 0, 0, 0, 0, 0, // Resource length (private resource gpr length)
							// private resource is the measured
							3, 0, // Header hob type resource descriptor
							0x30, 0, // Header hob length (48)
							0, 0, 0, 0, // Header reserved
							0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Owner (zeros)
							0, 0, 0, 0, // Resource type system memory (0)
							7, 0, 0, 0, // Resource attribute TD HOB base attributes present, initialized, tested 111b
							0, 0, 0xe0, 0xff, 0, 0, 0, 0, // Physical start (private resource gpr start)
							0xa8, 0, 0, 0, 0, 0, 0, 0, // Resource length (private resource gpr length)
							// end of hob list
							0xff, 0xff, 8, 0, 0, 0, 0, 0,
							// 0xe0 - 0xa0 padding
							0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
							0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
							0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
							0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						},
					},
					{GPR: GuestPhysicalRegion{Start: 0xffe00000, Length: 168},
						HostBuffer: []byte{
							// TDX metadata GUID
							0xf3, 0xf9, 0xea, 0xe9, 0x8e, 0x16, 0xd5, 0x44, 0xa8, 0xeb, 0x7f, 0x4d, 0x87, 0x38, 0xf6, 0xae,

							'T', 'D', 'V', 'F', // Signature
							80, 0, 0, 0, // Length
							1, 0, 0, 0, // Version
							2, 0, 0, 0, // Section count
							0, 0, 0, 0, // Data offset
							0, 0, 0, 0, // Data size
							0, 0, 0, 0, 1, 0, 0, 0, // Memory base
							0xe0, 0, 0, 0, 0, 0, 0, 0, // Memory size
							2, 0, 0, 0, // Section type TD HOB not counted towards the firmware volumes.
							0x51, 0, 0, 0, // Metadata attributes extendmr [end of first section]
							0, 0, 0, 0, // Data offset
							168, 0, 0, 0, // Data size
							0, 0, 0xe0, 0xff, 0, 0, 0, 0, // Memory base
							168, 0, 0, 0, 0, 0, 0, 0, // Memory size
							0, 0, 0, 0, // Section type
							0xcd, 0xab, 0x21, 0x43, // Metadata attributes extendmr

							0x98, 0, 0, 0, // Offset points to the beginning of this input.
							22, 0, // size of this entry
							// "e47a6535-984a-4798-865e-4685a7bf8ec2"
							0x35, 0x65, 0x7a, 0xe4, 0x4a, 0x98, 0x98, 0x47, 0x86, 0x5e, 0x46, 0x85, 0xa7, 0xbf, 0x8e, 0xc2,
							40, 0, // size of the whole table including the footer
							// FwGuidTableFooter
							0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d,
							// End padding
							0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
							0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						},
					},
				},
				TDHOBregion: &MaterialGuestPhysicalRegion{
					GPR: GuestPhysicalRegion{Start: 0x100000000, Length: 0xe0},
					// The TD HOB is constructed, not a region of the firmware binary.
					HostBuffer: []byte{1, 0, // Header hob type
						0x38, 0, // Header hob length (56)
						0, 0, 0, 0, // Header reserved
						9, 0, 0, 0, // version
						0, 0, 0, 0, // boot mode
						0, 0, 0, 0, 0, 0, 0, 0, // efi memory top
						0, 0, 0, 0, 0, 0, 0, 0, // efi memory bottom
						0, 0, 0, 0, 0, 0, 0, 0, // efi free memory top
						0, 0, 0, 0, 0, 0, 0, 0, // efi free memory bottom
						0x98, 0, 0, 0, 1, 0, 0, 0, // efi end of hob list (gpr start plus hob size)
						// private resource above 4GiB
						3, 0, // Header hob type resource descriptor
						0x30, 0, // Header hob length (48)
						0, 0, 0, 0, // Header reserved
						0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Owner (zeros)
						0, 0, 0, 0, // Resource type system memory (0) because early accept disabled
						7, 0, 0, 0, // Resource attribute TD HOB base attributes present, initialized, tested
						0, 0, 0, 0, 1, 0, 0, 0, // Physical start (private resource gpr start)
						0xe0, 0, 0, 0, 0, 0, 0, 0, // Resource length (private resource gpr length)
						// private resource is the measured
						3, 0, // Header hob type resource descriptor
						0x30, 0, // Header hob length (48)
						0, 0, 0, 0, // Header reserved
						0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Owner (zeros)
						0, 0, 0, 0, // Resource type system memory (0)
						7, 0, 0, 0, // Resource attribute TD HOB base attributes present, initialized, tested 111b
						0, 0, 0xe0, 0xff, 0, 0, 0, 0, // Physical start (private resource gpr start)
						0xa8, 0, 0, 0, 0, 0, 0, 0, // Resource length (private resource gpr length)
						// end of hob list
						0xff, 0xff, 8, 0, 0, 0, 0, 0,
						// 0xe0 - 0xa0 padding
						0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
						0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					},
				},
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.p.parse(tc.firmware, tc.guestRAMbanks)
			if !match.Error(err, tc.wantErr) {
				t.Errorf("%v.parse(%v, %v) returned error %v, want error %v", tc.p, tc.firmware, tc.guestRAMbanks, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			// Ensure that the parser's regions are the output for coverage since we're only comparing the
			// parser end states.
			if diff := cmp.Diff(tc.p.Regions, got); diff != "" {
				t.Errorf("%v.parse(%v, %v) returned diff (-want +got): %v", tc.p, tc.firmware, tc.guestRAMbanks, diff)
			}
			if diff := cmp.Diff(tc.want, tc.p); diff != "" {
				t.Errorf("parse(%v, %v) returned diff (-want +got): %v", tc.firmware, tc.guestRAMbanks, diff)
				t.Logf(" Got TD HOB:\n%s", hex.Dump(tc.p.TDHOBregion.HostBuffer))
				t.Logf("Want TD HOB:\n%s", hex.Dump(tc.want.TDHOBregion.HostBuffer))
			}
		})
	}
}
