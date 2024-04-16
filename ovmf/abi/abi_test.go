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
	"bytes"
	"testing"

	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

// FwGUIDTable footer as it appears in OVMF binary
var ovmfFooter = []byte{0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d}

type putter interface {
	Put(b []byte) error
}

func TestEfiGuidParseRoundtrip(t *testing.T) {
	efiguid, err := parseEFIGUID(ovmfFooter)
	if err != nil {
		t.Error(err)
	}
	var got uuid.UUID
	if err := efiguid.Put(got[:]); err != nil {
		t.Error(err)
	}
	if !bytes.Equal(got[:], ovmfFooter) {
		t.Errorf("parseEFIGUID(%v).Put(%v) != %v", ovmfFooter, got, ovmfFooter)
	}
	wantErr := "incorrect data size for EFI GUID"
	if _, err := parseEFIGUID(nil); !match.Error(err, wantErr) {
		t.Errorf("parseEFIGUID(nil) = %v, want error %q", err, wantErr)
	}
}

func TestEfiGuidConversion(t *testing.T) {
	efiguid, err := parseEFIGUID(ovmfFooter)
	if err != nil {
		t.Error(err)
	}
	got := convertEFIGUID(efiguid)
	want := uuid.MustParse(FwGUIDTableFooterGUID)
	if got != want {
		t.Errorf("convertEFIGUID(parseEFIGUID(%v)) = %v, want %v", ovmfFooter, got, want)
	}
}

func TestEfiGuidPut(t *testing.T) {
	efiOvmfGUID := EFIGUID{Data1: 0x96b582de, Data2: 0x1fb2, Data3: 0x45f7, Data4: [...]byte{0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d}}
	var dest [16]byte
	if err := efiOvmfGUID.Put(dest[:]); err != nil {
		t.Errorf("%v.Put([16]byte{}) = %v. Want nil", efiOvmfGUID, err)
	}
	if !bytes.Equal(dest[:], ovmfFooter) {
		t.Errorf("%v.Put(b) resulted in %v, want %v", efiOvmfGUID, dest[:], ovmfFooter)
	}
	wantErr := "data too small for GUID"
	if err := efiOvmfGUID.Put(nil); !match.Error(err, wantErr) {
		t.Errorf("%v.Put(nil) = %v. Want error %q", efiOvmfGUID, err, wantErr)
	}
}

func TestTDXPut(t *testing.T) {
	tcs := []struct {
		name    string
		dest    []byte
		h       putter
		want    []byte
		wantErr string
	}{
		{
			name: "metadata descriptor success",
			dest: make([]byte, 16),
			h: &TDXMetadataDescriptor{
				Signature:    0x12345678,
				Length:       0xabcdef99,
				Version:      0x4321dcba,
				SectionCount: 0xc0de,
			},
			want: []byte{0x78, 0x56, 0x34, 0x12, 0x99, 0xef, 0xcd, 0xab, 0xba, 0xdc, 0x21, 0x43, 0xde, 0xc0, 0, 0},
		},
		{
			name:    "metadata descriptor dest too small",
			dest:    make([]byte, 15),
			h:       &TDXMetadataDescriptor{},
			wantErr: "data too small for TDX metadata descriptor: 15 < 16",
		},
		{
			name: "metadata section success",
			dest: make([]byte, 32),
			h: &TDXMetadataSection{
				DataOffset:                 0,
				DataSize:                   0x200000,
				MemoryBase:                 0xffe00000,
				MemorySize:                 0x200000,
				SectionType:                TDXMetadataSectionTypeTDHOB,
				MetadataAttributesExtendmr: 0x4321abcd,
			},
			want: []byte{
				0, 0, 0, 0, // Data offset
				0, 0, 0x20, 0, // Data size
				0, 0, 0xe0, 0xff, 0, 0, 0, 0, // Memory base
				0, 0, 0x20, 0, 0, 0, 0, 0, // Memory size
				2, 0, 0, 0, // Section type
				0xcd, 0xab, 0x21, 0x43, // Metadata attributes extendmr
			},
		},
		{
			name:    "metadata section dest too small",
			dest:    make([]byte, 31),
			h:       &TDXMetadataSection{},
			wantErr: "data too small for TDX metadata section: 31 < 32",
		},
		{
			name:    "tdx metadata nil header",
			h:       &TDXMetadata{},
			wantErr: "TDX metadata descriptor is nil",
		},
		{
			name:    "tdx metadata dest too small",
			h:       &TDXMetadata{Header: &TDXMetadataDescriptor{}},
			wantErr: "data too small",
		},
		{
			name: "tdx metadata dest too small for sections",
			dest: make([]byte, 47),
			h: &TDXMetadata{
				Header:   &TDXMetadataDescriptor{SectionCount: 1},
				Sections: []*TDXMetadataSection{{}},
			},
			wantErr: "data too small for 1 TDX metadata sections: 47 < 48",
		},
		{
			name: "tdx metadata ill formed",
			dest: make([]byte, 100),
			h: &TDXMetadata{
				Header: &TDXMetadataDescriptor{
					SectionCount: 1,
				},
				Sections: []*TDXMetadataSection{{}, {}},
			},
			wantErr: "illformed",
		}, {
			name: "tdx metadata success",
			dest: make([]byte, 80),
			h: &TDXMetadata{
				Header: &TDXMetadataDescriptor{
					Signature:    0x12345678,
					Length:       0xabcdef99,
					Version:      0x4321dcba,
					SectionCount: 2,
				},
				Sections: []*TDXMetadataSection{
					{
						DataOffset:                 2,
						DataSize:                   0,
						MemoryBase:                 0x100000000,
						MemorySize:                 0x3400000000,
						SectionType:                TDXMetadataSectionTypeTempMem,
						MetadataAttributesExtendmr: 0x51,
					},
					{
						DataOffset:                 0,
						DataSize:                   0x200000,
						MemoryBase:                 0xffe00000,
						MemorySize:                 0x200000,
						SectionType:                TDXMetadataSectionTypeBFV,
						MetadataAttributesExtendmr: 0x4321abcd,
					},
				},
			},
			want: []byte{
				0x78, 0x56, 0x34, 0x12, // Signature
				0x99, 0xef, 0xcd, 0xab, // Length
				0xba, 0xdc, 0x21, 0x43, // Version
				2, 0, 0, 0, // Section count
				2, 0, 0, 0, // Data offset
				0, 0, 0, 0, // Data size
				0, 0, 0, 0, 1, 0, 0, 0, // Memory base
				0, 0, 0, 0, 0x34, 0, 0, 0, // Memory size
				3, 0, 0, 0, // Section type
				0x51, 0, 0, 0, // Metadata attributes extendmr
				0, 0, 0, 0, // Data offset
				0, 0, 0x20, 0, // Data size
				0, 0, 0xe0, 0xff, 0, 0, 0, 0, // Memory base
				0, 0, 0x20, 0, 0, 0, 0, 0, // Memory size
				0, 0, 0, 0, // Section type
				0xcd, 0xab, 0x21, 0x43, // Metadata attributes extendmr
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.h.Put(tc.dest); !match.Error(err, tc.wantErr) {
				t.Errorf("%v.Put(b) = %v. Want error %q", tc.h, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if !bytes.Equal(tc.dest, tc.want) {
				t.Errorf("%v.Put(b) wrote %v, want %v", tc.h, tc.dest, tc.want)
			}
		})
	}
}

func TestTDXMetadataDescriptorFromBytes(t *testing.T) {
	tcs := []struct {
		name    string
		bytes   []byte
		want    *TDXMetadataDescriptor
		wantErr string
	}{
		{
			name:  "metadata descriptor success",
			bytes: []byte{0x78, 0x56, 0x34, 0x12, 0x99, 0xef, 0xcd, 0xab, 0xba, 0xdc, 0x21, 0x43, 0xde, 0xc0, 0, 0},
			want: &TDXMetadataDescriptor{
				Signature:    0x12345678,
				Length:       0xabcdef99,
				Version:      0x4321dcba,
				SectionCount: 0xc0de,
			},
		},
		{
			name:    "metadata descriptor too small",
			bytes:   make([]byte, 15),
			wantErr: "data too small for TDX metadata descriptor: 15 < 16",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TDXMetadataDescriptorFromBytes(tc.bytes)
			if !match.Error(err, tc.wantErr) {
				t.Errorf("TDXMetadataDescriptorFromBytes(b) = %v. Want error %q", err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("TDXMetadataDescriptorFromBytes(%v) = %v, want %v", tc.bytes, got, tc.want)
			}
		})
	}
}

func TestTDXMetadataSectionFromBytes(t *testing.T) {
	tcs := []struct {
		name    string
		bytes   []byte
		want    *TDXMetadataSection
		wantErr string
	}{
		{
			name: "metadata section success",
			bytes: []byte{0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0, 1, 0, 0, 0,
				0, 0, 0, 0, 0x34, 0, 0, 0,
				3, 0, 0, 0,
				0x51, 0, 0, 0},
			want: &TDXMetadataSection{
				DataOffset:                 0,
				DataSize:                   0,
				MemoryBase:                 0x100000000,
				MemorySize:                 0x3400000000,
				SectionType:                TDXMetadataSectionTypeTempMem,
				MetadataAttributesExtendmr: 0x51,
			},
		},
		{
			name:    "metadata section too small",
			bytes:   make([]byte, 31),
			wantErr: "data too small for TDX metadata section: 31 < 32",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TDXMetadataSectionFromBytes(tc.bytes)
			if !match.Error(err, tc.wantErr) {
				t.Errorf("TDXMetadataSectionFromBytes(b) = %v. Want error %q", err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("TDXMetadataSectionFromBytes(%v) = %v, want %v", tc.bytes, got, tc.want)
			}
		})
	}
}

func TestTDXMetadataFromBytes(t *testing.T) {
	tcs := []struct {
		name    string
		bytes   []byte
		want    *TDXMetadata
		wantErr string
	}{
		{
			name: "metadata success",
			bytes: []byte{
				0x78, 0x56, 0x34, 0x12, // Signature
				0x99, 0xef, 0xcd, 0xab, // Length
				0xba, 0xdc, 0x21, 0x43, // Version
				2, 0, 0, 0, // Section count
				0, 0, 0, 0, // Data offset
				0, 0, 0, 0, // Data size
				0, 0, 0, 0, 1, 0, 0, 0, // Memory base
				0, 0, 0, 0, 0x34, 0, 0, 0, // Memory size
				3, 0, 0, 0, // Section type
				0x51, 0, 0, 0, // Metadata attributes extendmr
				1, 0, 0, 0, // Data offset
				0, 0, 0x20, 0, // Data size
				0, 0, 0xe0, 0xff, 0, 0, 0, 0, // Memory base
				0, 0, 0x20, 0, 0, 0, 0, 0, // Memory size
				0, 0, 0, 0, // Section type
				0xcd, 0xab, 0x21, 0x43, // Metadata attributes extendmr
			},
			want: &TDXMetadata{
				Header: &TDXMetadataDescriptor{
					Signature:    0x12345678,
					Length:       0xabcdef99,
					Version:      0x4321dcba,
					SectionCount: 2,
				},
				Sections: []*TDXMetadataSection{
					{
						DataOffset:                 0,
						DataSize:                   0,
						MemoryBase:                 0x100000000,
						MemorySize:                 0x3400000000,
						SectionType:                TDXMetadataSectionTypeTempMem,
						MetadataAttributesExtendmr: 0x51,
					},
					{
						DataOffset:                 1,
						DataSize:                   0x200000,
						MemoryBase:                 0xffe00000,
						MemorySize:                 0x200000,
						SectionType:                TDXMetadataSectionTypeBFV,
						MetadataAttributesExtendmr: 0x4321abcd,
					},
				},
			},
		},
		{
			name:    "metadata descriptor fail",
			wantErr: "could not parse TDX metadata descriptor: data too small",
		},
		{
			name: "remainder too small",
			bytes: []byte{0x78, 0x56, 0x34, 0x12, // Signature
				0x99, 0xef, 0xcd, 0xab, // Length
				0xba, 0xdc, 0x21, 0x43, // Version
				2, 0, 0, 0, // Section count
				0, 0, 0, 0, 0, 0, // Not enough data..
			},
			wantErr: "data too small for expected section count 2: 6 < 64",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TDXMetadataFromBytes(tc.bytes)
			if !match.Error(err, tc.wantErr) {
				t.Errorf("TDXMetadataFromBytes(b) = %v. Want error %q", err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("TDXMetadataFromBytes(%v) = %v, want %v", tc.bytes, got, tc.want)
			}
		})
	}
}
