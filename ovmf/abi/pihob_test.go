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
	"fmt"
	"io"
	"testing"

	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

// failWriter is a writer that fails after a certain number of bytes are written. This is to get
// full test coverage.
type failWriter struct {
	after  int
	called int
	buf    *bytes.Buffer
}

func newFailWriter(after int) *failWriter {
	return &failWriter{after: after, called: 0, buf: bytes.NewBuffer(nil)}
}

func (f *failWriter) Bytes() []byte {
	return f.buf.Bytes()
}

func (f *failWriter) Write(b []byte) (int, error) {
	f.called++
	if f.after > 0 {
		f.after--
		return f.buf.Write(b)
	}
	return 0, fmt.Errorf("fail%d", f.called)
}

type writable interface {
	WriteTo(w io.Writer) (int64, error)
}

func TestWriteTo(t *testing.T) {
	tcs := []struct {
		name      string
		w         *failWriter
		h         writable
		want      int64
		wantErr   string
		wantBytes []byte
	}{
		{
			name:    "header fail1", // Hob type
			w:       newFailWriter(0),
			h:       EFIHOBGenericHeader{},
			wantErr: "fail1",
		},
		{
			name:    "header fail2", // Length
			w:       newFailWriter(1),
			h:       EFIHOBGenericHeader{},
			wantErr: "fail2",
		},
		{
			name:    "header fail3", // Reserved
			w:       newFailWriter(2),
			h:       EFIHOBGenericHeader{},
			wantErr: "fail3",
		},
		{
			name:      "header handoff",
			w:         newFailWriter(3),
			h:         EFIHOBGenericHeader{HobType: EFIHOBTypeEndOfHOBList, HobLength: 2},
			want:      SizeofHOBGenericHeader,
			wantBytes: []byte{0xff, 0xff, 2, 0, 0, 0, 0, 0},
		},
		{
			name:    "handoff info fail1", // Header hob type
			w:       newFailWriter(0),
			h:       EFIHOBHandoffInfoTable{},
			wantErr: "fail1",
		},
		{
			name:    "handoff info fail2", // Header hob length
			w:       newFailWriter(1),
			h:       EFIHOBHandoffInfoTable{},
			wantErr: "fail2",
		},
		{
			name:    "handoff info fail3", // Header reserved
			w:       newFailWriter(2),
			h:       EFIHOBHandoffInfoTable{},
			wantErr: "fail3",
		},
		{
			name:    "handoff info fail4", // Version
			w:       newFailWriter(3),
			h:       EFIHOBHandoffInfoTable{},
			wantErr: "fail4",
		},
		{
			name:    "handoff info fail5", // Boot mode
			w:       newFailWriter(4),
			h:       EFIHOBHandoffInfoTable{},
			wantErr: "fail5",
		},
		{
			name:    "handoff info fail6", // Efi memory top
			w:       newFailWriter(5),
			h:       EFIHOBHandoffInfoTable{},
			wantErr: "fail6",
		},
		{
			name:    "handoff info fail7", // Efi memory bottom
			w:       newFailWriter(6),
			h:       EFIHOBHandoffInfoTable{},
			wantErr: "fail7",
		},
		{
			name:    "handoff info fail8", // Efi free memory top
			w:       newFailWriter(7),
			h:       EFIHOBHandoffInfoTable{},
			wantErr: "fail8",
		},
		{
			name:    "handoff info fail9", // Efi free memory bottom
			w:       newFailWriter(8),
			h:       EFIHOBHandoffInfoTable{},
			wantErr: "fail9",
		},
		{
			name:    "handoff info fail10", // Efi end of hob list
			w:       newFailWriter(9),
			h:       EFIHOBHandoffInfoTable{},
			wantErr: "fail10",
		},
		{
			name: "handoff info",
			w:    newFailWriter(10),
			h: EFIHOBHandoffInfoTable{
				Header:              EFIHOBGenericHeader{HobType: EFIHOBTypeHandoff, HobLength: 0x7fff},
				Version:             EFIHOBHandoffTableVersion,
				BootMode:            BootWithFullConfiguration,
				EfiMemoryTop:        0xc0000000,
				EfiMemoryBottom:     10,
				EfiFreeMemoryTop:    0xffe00000,
				EfiFreeMemoryBottom: 0xff0000f0,
				EfiEndOfHobList:     0xabcdef0123456789,
			},
			want: SizeOfEFIHOBHandoffInfoTable,
			wantBytes: []byte{1, 0, 0xff, 0x7f, 0, 0, 0, 0, // header
				9, 0, 0, 0, // version
				0, 0, 0, 0, // boot mode
				0, 0, 0, 0xc0, 0, 0, 0, 0, // efi memory top
				10, 0, 0, 0, 0, 0, 0, 0, // efi memory bottom
				0, 0, 0xe0, 0xff, 0, 0, 0, 0, // efi free memory top
				0xf0, 0, 0, 0xff, 0, 0, 0, 0, // efi free memory bottom
				0x89, 0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, // efi end of hob list
			},
		},
		{
			name:    "resource descriptor fail1", // Header hob type
			w:       newFailWriter(0),
			h:       EFIHOBResourceDescriptor{},
			wantErr: "fail1",
		},
		{
			name:    "resource descriptor fail2", // Header hob length
			w:       newFailWriter(1),
			h:       EFIHOBResourceDescriptor{},
			wantErr: "fail2",
		},
		{
			name:    "resource descriptor fail3", // Header reserved
			w:       newFailWriter(2),
			h:       EFIHOBResourceDescriptor{},
			wantErr: "fail3",
		},
		{
			name:    "resource descriptor fail4", // Owner
			w:       newFailWriter(3),
			h:       EFIHOBResourceDescriptor{},
			wantErr: "fail4",
		},
		{
			name:    "resource descriptor fail5", // Resource type
			w:       newFailWriter(4),
			h:       EFIHOBResourceDescriptor{},
			wantErr: "fail5",
		},
		{
			name:    "resource descriptor fail6", // Resource attribute
			w:       newFailWriter(5),
			h:       EFIHOBResourceDescriptor{},
			wantErr: "fail6",
		},
		{
			name:    "resource descriptor fail7", // Physical start
			w:       newFailWriter(6),
			h:       EFIHOBResourceDescriptor{},
			wantErr: "fail7",
		},
		{
			name:    "resource descriptor fail8", // Resource length
			w:       newFailWriter(7),
			h:       EFIHOBResourceDescriptor{},
			wantErr: "fail8",
		},
		{
			name: "resource descriptor",
			w:    newFailWriter(8),
			h: EFIHOBResourceDescriptor{
				Header:            EFIHOBGenericHeader{HobType: EFIHOBTypeResourceDescriptor, HobLength: 5},
				Owner:             EFIGUID{Data1: 0xabcdef99, Data2: 0x4312, Data3: 0x8954, Data4: [...]byte{0, 1, 2, 3, 4, 5, 6, 7}},
				ResourceType:      EFIResourceMemoryUnaccepted,
				ResourceAttribute: EFIResourceAttributePresent | EFIResourceAttributeInitialized | EFIResourceAttributeNeedsEarlyAccept,
				PhysicalStart:     0xffe00000,
				ResourceLength:    0x200000,
			},
			want: SizeofEFIHOBResourceDescriptor,
			wantBytes: []byte{3, 0, 5, 0, 0, 0, 0, 0, // header
				0x99, 0xef, 0xcd, 0xab, 0x12, 0x43, 0x54, 0x89, 0, 1, 2, 3, 4, 5, 6, 7, // Owner
				7, 0, 0, 0, // Resource type
				3, 0, 0, 0x10, // Resource attribute
				0, 0, 0xe0, 0xff, 0, 0, 0, 0, // Physical start
				0, 0, 0x20, 0, 0, 0, 0, 0, // Resource length
			},
		},
		{
			name: "guid hob fail 1",
			w:    newFailWriter(0),
			h: EFIHOBGUID{
				Header: EFIHOBGenericHeader{
					HobType:   EFIHOBTypeGUIDExtension,
					HobLength: 27,
				},
				GUID: EFIGUID{Data1: 0xabcdef99, Data2: 0x4312, Data3: 0x8954, Data4: [...]byte{0, 1, 2, 3, 4, 5, 6, 7}},
				Data: []byte("foo"),
			},
			wantErr: "fail1",
		},
		{
			name: "guid hob fail 2",
			w:    newFailWriter(1),
			h: EFIHOBGUID{
				Header: EFIHOBGenericHeader{
					HobType:   EFIHOBTypeGUIDExtension,
					HobLength: 27,
				},
				GUID: EFIGUID{Data1: 0xabcdef99, Data2: 0x4312, Data3: 0x8954, Data4: [...]byte{0, 1, 2, 3, 4, 5, 6, 7}},
				Data: []byte("foo"),
			},
			wantErr: "fail2",
		},
		{
			name: "guid hob fail 3",
			w:    newFailWriter(2),
			h: EFIHOBGUID{
				Header: EFIHOBGenericHeader{
					HobType:   EFIHOBTypeGUIDExtension,
					HobLength: 27,
				},
				GUID: EFIGUID{Data1: 0xabcdef99, Data2: 0x4312, Data3: 0x8954, Data4: [...]byte{0, 1, 2, 3, 4, 5, 6, 7}},
				Data: []byte("foo"),
			},
			wantErr: "fail3",
		},
		{
			name: "guid hob fail 4",
			w:    newFailWriter(3),
			h: EFIHOBGUID{
				Header: EFIHOBGenericHeader{
					HobType:   EFIHOBTypeGUIDExtension,
					HobLength: 27,
				},
				GUID: EFIGUID{Data1: 0xabcdef99, Data2: 0x4312, Data3: 0x8954, Data4: [...]byte{0, 1, 2, 3, 4, 5, 6, 7}},
				Data: []byte("foo"),
			},
			wantErr: "fail4",
		},
		{
			name: "guid hob fail 5",
			w:    newFailWriter(4),
			h: EFIHOBGUID{
				Header: EFIHOBGenericHeader{
					HobType:   EFIHOBTypeGUIDExtension,
					HobLength: 27,
				},
				GUID: EFIGUID{Data1: 0xabcdef99, Data2: 0x4312, Data3: 0x8954, Data4: [...]byte{0, 1, 2, 3, 4, 5, 6, 7}},
				Data: []byte("foo"),
			},
			wantErr: "fail5",
		},
		{
			name: "guid hob",
			w:    newFailWriter(6),
			h: EFIHOBGUID{
				Header: EFIHOBGenericHeader{
					HobType:   EFIHOBTypeGUIDExtension,
					HobLength: 27,
				},
				GUID: EFIGUID{Data1: 0xabcdef99, Data2: 0x4312, Data3: 0x8954, Data4: [...]byte{0, 1, 2, 3, 4, 5, 6, 7}},
				Data: []byte("foo"),
			},
			want: int64(SizeofHOBGUID + len([]byte("foo"))),
			wantBytes: []byte{
				4, 0, // type
				27, 0, // length
				0, 0, 0, 0, // reserved
				0x99, 0xef, 0xcd, 0xab, 0x12, 0x43, 0x54, 0x89, 0, 1, 2, 3, 4, 5, 6, 7, // GUID
				'f', 'o', 'o',
			},
		},
		{
			name: "created guid hob",
			w:    newFailWriter(6),
			h: func() EFIHOBGUID {
				guid := uuid.MustParse(Tcg800155PlatformIDEventHobGUID)
				r, err := CreateEFIHOBGUID(guid, []byte("foo"))
				if err != nil {
					t.Fatalf("CreateEFIHOBGUID(%v) = %v, want nil", guid, err)
				}
				return r
			}(),
			want: int64(SizeofHOBGUID + 8), // len("foo") rounds to the nearest 8.
			wantBytes: []byte{
				4, 0, // type
				32, 0, // length
				0, 0, 0, 0, // reserved
				0x69, 0xbc, 0xc3, 0xe2, 0x5c, 0x61, 0x5b, 0x4b, 0x8e, 0x5c, 0xa0, 0x33, 0xa9, 0xc2, 0x5e, 0xd6, // GUID
				'f', 'o', 'o', 0, 0, 0, 0, 0,
			},
		},
		{
			name: "guid hob bad type",
			w:    newFailWriter(6),
			h: EFIHOBGUID{
				Header: EFIHOBGenericHeader{
					HobType:   EFIHOBTypeResourceDescriptor,
					HobLength: 32,
				},
				GUID: EFIGUID{Data1: 0xabcdef99, Data2: 0x4312, Data3: 0x8954, Data4: [...]byte{0, 1, 2, 3, 4, 5, 6, 7}},
				Data: append([]byte("foo"), 0, 0, 0, 0, 0),
			},
			wantErr: "invalid HOB type: 3",
		},
		{
			name: "guid hob bad length",
			w:    newFailWriter(6),
			h: EFIHOBGUID{
				Header: EFIHOBGenericHeader{
					HobType:   EFIHOBTypeGUIDExtension,
					HobLength: 33,
				},
				GUID: EFIGUID{Data1: 0xabcdef99, Data2: 0x4312, Data3: 0x8954, Data4: [...]byte{0, 1, 2, 3, 4, 5, 6, 7}},
				Data: append([]byte("foo"), 0, 0, 0, 0, 0),
			},
			wantErr: "invalid HOB length: 33, want 32",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.h.WriteTo(tc.w)
			if !match.Error(err, tc.wantErr) {
				t.Errorf("WriteTo(%v) = %v errored unexpectedly. Want %q", tc.h, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("%v.WriteTo(_) = %d, want %d", tc.h, got, tc.want)
			}
			if tc.wantErr != "" {
				return
			}
			got2 := tc.w.Bytes()
			if int64(len(got2)) != tc.want {
				t.Errorf("%v.WriteTo(b) wrote %d bytes, want %d", tc.h, len(got2), tc.want)
			}
			if diff := cmp.Diff(got2, tc.wantBytes); diff != "" {
				t.Errorf("%v.WriteTo(b) got %v. Want %v", tc.h, got2, tc.wantBytes)
			}
		})
	}
}

func TestTcgGUID(t *testing.T) {
	var guid [16]byte
	if err := PutUUID(guid[:], uuid.MustParse(Tcg800155PlatformIDEventHobGUID)); err != nil {
		t.Fatal(err)
	}
	eguid, err := parseEFIGUID(guid[:])
	if err != nil {
		t.Fatal(err)
	}
	want := EFIGUID{
		Data1: 0xe2c3bc69, // Hexdump looks like bc69 e2c3 615c 4b5b 5c8e 33a0 c2a9 d65e
		Data2: 0x615c,
		Data3: 0x4b5b,
		Data4: [...]byte{0x8e, 0x5c, 0xa0, 0x33, 0xa9, 0xc2, 0x5e, 0xd6},
	}
	if diff := cmp.Diff(want, eguid); diff != "" {
		t.Fatalf("EFI_GUID diff (-want +got): %s", diff)
	}
}
