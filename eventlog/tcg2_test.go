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

package eventlog

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

const (
	myGUID  = "6a7b6885-92bc-40cd-9fb5-300f9d1eb0ed"
	rimGUID = "c51b6d7f-9c2a-42d6-be47-ca1368bdc333"
)

var (
	myEfiGUID = []byte{0x85, 0x68, 0x7b, 0x6a, 0xbc, 0x92, 0xcd, 0x40, 0x9f, 0xb5, 0x30, 0x0f, 0x9d, 0x1e, 0xb0, 0xed}
	efiRIM    = []byte{0x7f, 0x6d, 0x1b, 0xc5, 0x2a, 0x9c, 0xd6, 0x42, 0xbe, 0x47, 0xca, 0x13, 0x68, 0xbd, 0xc3, 0x33}
	fields    = [][]byte{
		binary.LittleEndian.AppendUint32(nil, 11129), // Platform Manufacturer ID
		efiRIM, // RIM GUID
		bytesizedArray([]byte("Google Compute Engine")),             // PlatformManufacturerStr
		bytesizedArray([]byte("PFModel")),                           // PlatformModel
		bytesizedArray([]byte("PFVersion")),                         // PlatformVersion
		bytesizedArray([]byte("Vanadium")),                          // FirmwareManufacturerStr
		binary.LittleEndian.AppendUint32(nil, 54494),                // FirmwareManufacturer ID
		bytesizedArray([]byte("2.0.0")),                             // FirmwareVersion
		binary.LittleEndian.AppendUint32(nil, RIMLocationVariable),  // RIM Locator Type
		sizedArray(append(myEfiGUID, 'V', 0, 'a', 0, 'r', 0, 0, 0)), // RIM Locator
		binary.LittleEndian.AppendUint32(nil, RIMLocationRaw),       // PlatformCertLocatorType
		sizedArray(nil), // PlatformCertLocator
	}
	goodStruct = &SP800155Event3{
		PlatformManufacturerID:  11129,
		ReferenceManifestGUID:   EfiGUID{UUID: uuid.MustParse(rimGUID)},
		PlatformManufacturerStr: ByteSizedArray{Data: []byte("Google Compute Engine")},
		PlatformModel:           ByteSizedArray{Data: []byte("PFModel")},
		PlatformVersion:         ByteSizedArray{Data: []byte("PFVersion")},
		FirmwareManufacturerStr: ByteSizedArray{Data: []byte("Vanadium")},
		FirmwareManufacturerID:  54494,
		FirmwareVersion:         ByteSizedArray{Data: []byte("2.0.0")},
		RIMLocatorType:          RIMLocationVariable,
		RIMLocator:              Uint32SizedArray{Data: append(myEfiGUID, 'V', 0, 'a', 0, 'r', 0, 0, 0)},
		PlatformCertLocatorType: RIMLocationRaw,
		PlatformCertLocator:     Uint32SizedArray{Data: []byte{}},
	}
)

func makeEvent(numFields int) []byte {
	var result []byte
	for i := 0; i < numFields; i++ {
		result = append(result, fields[i]...)
	}
	return result
}

func combine(base []byte, additions ...[]byte) []byte {
	result := base
	for _, addition := range additions {
		result = append(result, addition...)
	}
	return result
}

func bytesizedArray(b []byte) []byte {
	return append([]byte{byte(len(b))}, b...)
}

func sizedArray(b []byte) []byte {
	return append(binary.LittleEndian.AppendUint32(nil, uint32(len(b))), b...)
}

func TestReadSp800155Event3(t *testing.T) {
	goodEvent := makeEvent(len(fields))
	tcs := []struct {
		name    string
		input   []byte
		want    *SP800155Event3
		wantErr string
	}{
		{
			name:  "happy path",
			input: goodEvent,
			want:  goodStruct,
		},
		{
			name:  "meager",
			input: make([]byte, 45),
			want: &SP800155Event3{PlatformManufacturerStr: ByteSizedArray{Data: []byte{}},
				PlatformModel:           ByteSizedArray{Data: []byte{}},
				PlatformVersion:         ByteSizedArray{Data: []byte{}},
				FirmwareManufacturerStr: ByteSizedArray{Data: []byte{}},
				FirmwareVersion:         ByteSizedArray{Data: []byte{}},
				PlatformCertLocator:     Uint32SizedArray{Data: []byte{}},
				RIMLocator:              Uint32SizedArray{Data: []byte{}},
			},
		},
		{
			name:    "truncated0",
			input:   makeEvent(0),
			wantErr: "failed to read PlatformManufacturerID as *uint32",
		},
		{
			name:    "truncated1",
			input:   makeEvent(1),
			wantErr: "failed to read ReferenceManifestGuid as *eventlog.EfiGUID",
		},
		{
			name:    "truncated2a",
			input:   makeEvent(2),
			wantErr: "failed to read PlatformManufacturerStr as *eventlog.ByteSizedArray",
		},
		{
			name:    "truncated2b",
			input:   append(makeEvent(2), 3),
			wantErr: "failed to read PlatformManufacturerStr as *eventlog.ByteSizedArray",
		},
		{
			name:    "truncated3",
			input:   makeEvent(3),
			wantErr: "failed to read PlatformModel as *eventlog.ByteSizedArray",
		},
		{
			name:    "truncated4",
			input:   makeEvent(4),
			wantErr: "failed to read PlatformVersion as *eventlog.ByteSizedArray: failed to read array size as *uint8",
		},
		{
			name:    "truncated5",
			input:   makeEvent(5),
			wantErr: "failed to read FirmwareManufacturerStr as *eventlog.ByteSizedArray",
		},
		{
			name:    "truncated6",
			input:   makeEvent(6),
			wantErr: "failed to read FirmwareManufacturerID as *uint32",
		},
		{
			name:    "truncated7",
			input:   makeEvent(7),
			wantErr: "failed to read FirmwareVersion as *eventlog.ByteSizedArray",
		},
		{
			name:    "truncated8",
			input:   makeEvent(8),
			wantErr: "failed to read RIMLocatorType as *uint32",
		},
		{
			name:    "truncated9",
			input:   makeEvent(9),
			wantErr: "failed to read RIMLocator as *eventlog.Uint32SizedArray",
		},
		{
			name:    "truncated10",
			input:   makeEvent(10),
			wantErr: "failed to read PlatformCertLocatorType as *uint32",
		},
		{
			name:    "truncated11",
			input:   makeEvent(11),
			wantErr: "failed to read PlatformCertLocator as *eventlog.Uint32SizedArray",
		},
		{
			name:    "a little more",
			input:   append(goodEvent, []byte("0123456789ab")...),
			wantErr: "12 bytes remaining of SP800155Event3",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := &SP800155Event3{}
			err := got.UnmarshalFromBytes(tc.input)
			if !match.Error(err, tc.wantErr) {
				t.Fatalf("UnmarshalFromBytes(%v) = %v errored unexpectedly. Want %q", tc.input, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Fatalf("unexpected diff (-got +want):\n%s", diff)
			}
		})
	}
}

func TestReadTcg2PCREventSp800155Event3(t *testing.T) {
	goodEvent := makeEvent(len(fields))
	tcs := []struct {
		name    string
		data    []byte
		want    *TCGPCREvent2
		wantErr string
	}{
		{
			name: "happy path",
			data: combine([]byte{2, 0, 0, 0},
				[]byte{5, 0, 0, 0},
				[]byte{2, 0, 0, 0},    // number of digests
				[]byte{tpmAlgSHA1, 0}, // algID uint16
				foosha1[:],
				[]byte{tpmAlgSHA256, 0}, // algID uint16
				foosha256[:],
				binary.LittleEndian.AppendUint32(nil, 16+uint32(len(goodEvent))), TcgSP800155Event3Signature[:],
				goodEvent),
			want: &TCGPCREvent2{
				PCRIndex:  2,
				EventType: 5,
				Digests: Uint32SizedArrayT[*TaggedDigest]{Array: []*TaggedDigest{
					{AlgID: tpmAlgSHA1, Digest: foosha1[:]},
					{AlgID: tpmAlgSHA256, Digest: foosha256[:]},
				}},
				EventData: TCGEventData{
					Event: goodStruct,
				},
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := &TCGPCREvent2{}
			if err := got.Unmarshal(bytes.NewBuffer(tc.data)); !match.Error(err, tc.wantErr) {
				t.Fatalf("ReadTCGPCREvent2(%v) = %v errored unexpectedly. Want %q", tc.data, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Fatalf("unexpected diff (-got +want):\n%s", diff)
			}
		})
	}
}

func TestWriteTcg2PCREventSp800155Event3(t *testing.T) {
	goodEvent := makeEvent(len(fields))
	tcs := []struct {
		name    string
		data    *TCGPCREvent2
		want    []byte
		wantErr string
	}{
		{
			name: "happy path",
			data: &TCGPCREvent2{
				PCRIndex:  2,
				EventType: 5,
				Digests: Uint32SizedArrayT[*TaggedDigest]{Array: []*TaggedDigest{
					{AlgID: tpmAlgSHA1, Digest: foosha1[:]},
					{AlgID: tpmAlgSHA256, Digest: foosha256[:]},
				}},
				EventData: TCGEventData{
					Event: goodStruct,
				},
			},
			want: combine([]byte{2, 0, 0, 0},
				[]byte{5, 0, 0, 0},
				[]byte{2, 0, 0, 0},    // number of digests
				[]byte{tpmAlgSHA1, 0}, // algID uint16
				foosha1[:],
				[]byte{tpmAlgSHA256, 0}, // algID uint16
				foosha256[:],
				binary.LittleEndian.AppendUint32(nil, 16+uint32(len(goodEvent))), TcgSP800155Event3Signature[:],
				goodEvent),
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			w := bytes.NewBuffer(nil)
			if err := tc.data.Marshal(w); !match.Error(err, tc.wantErr) {
				t.Fatalf("WriteTCGPCREvent2(%v) = %v errored unexpectedly. Want %q", tc.data, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			got := w.Bytes()
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Fatalf("unexpected diff (-got +want):\n%s", diff)
			}
		})
	}
}
