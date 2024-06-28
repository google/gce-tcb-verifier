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

package endorse

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/google/gce-tcb-verifier/eventlog"
	oabi "github.com/google/gce-tcb-verifier/ovmf/abi"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	evpb "github.com/google/gce-tcb-verifier/proto/events"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func combine(base []byte, rest ...[]byte) []byte {
	combined := base
	for _, bs := range rest {
		combined = append(combined, bs...)
	}
	return combined
}

// Intended encoding vs illegible hardcoded array.
func TestRimVar(t *testing.T) {
	var efiGUID [16]byte
	oabi.PutUUID(efiGUID[:], uuid.MustParse(googleEfiVariable))
	want := efiGUID[:]
	for _, c := range []byte(sp800155Variable) {
		want = binary.LittleEndian.AppendUint16(want, uint16(c))
	}
	want = append(want, 0, 0)
	if !bytes.Equal(rimVar, want) {
		t.Errorf("rimVar = %v, want %v", rimVar, want)
	}
}

func TestMakeEvents(t *testing.T) {
	var digest [48]byte
	for i := byte(0); i < 48; i++ {
		digest[i] = i
	}
	golden := &epb.VMGoldenMeasurement{Digest: digest[:]}
	goldenBytes, _ := proto.Marshal(golden)
	e := &epb.VMLaunchEndorsement{SerializedUefiGolden: goldenBytes}
	rimGUIDsrc := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}
	// Version 4 Variant 10, so 7th and 9th bytes get modified.
	rimEFIGUID := []byte{3, 2, 1, 0, 5, 4, 0x7, 0x46, 0x88, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}
	blob, err := makeEvents(bytes.NewBuffer(rimGUIDsrc), e)
	if err != nil {
		t.Fatalf("makeEvents(%v) failed: %v", e, err)
	}
	evtpb := &evpb.Sp800155Events{}
	if err := proto.Unmarshal(blob, evtpb); err != nil {
		t.Fatalf("failed to unmarshal Sp800155Events: %v", err)
	}
	if len(evtpb.Events) != 2 {
		t.Errorf("evtpb.TcgPcrEvent2S = %v, want length 2", evtpb.Events)
	}

	varEvt := combine([]byte("SP800-155 Event3"),
		binary.LittleEndian.AppendUint32(nil, 11129), // PlatformManufacturerID
		rimEFIGUID, // ReferenceManifestGuid
		append([]byte{byte(len(googleManufacturer) + 1)}, []byte(googleManufacturer+"\x00")...), // PlatformManufacturerStr
		append([]byte{byte(len(platformModel) + 1)}, []byte(platformModel+"\x00")...),           // PlatformModel
		[]byte{1, 0}, // PlatformVersion
		append([]byte{byte(len(googleManufacturer) + 1)}, []byte(googleManufacturer+"\x00")...), // FirmwareManufacturerStr
		binary.LittleEndian.AppendUint32(nil, 11129),                                            // FirmwareManufacturerID
		append([]byte{byte(len(firmwareVersion)) + 1}, []byte(firmwareVersion+"\x00")...),       // FirmwareVersion
		binary.LittleEndian.AppendUint32(nil, eventlog.RIMLocationVariable),                     // RIM locator type
		binary.LittleEndian.AppendUint32(nil, uint32(len(rimVar))),                              // RIM locator (length)
		rimVar,             // Rim locator (data)
		[]byte{0, 0, 0, 0}, // Platform cert locator type
		[]byte{0, 0, 0, 0}, // Platform cert length
	)
	if diff := cmp.Diff(varEvt, evtpb.Events[0]); diff != "" {
		t.Errorf("makeEvents(%v) = %v..., want %v...: diff (-want, +got) %s", e, evtpb.Events[0], varEvt, diff)
	}
	wantURILen := 282
	uri := evtpb.Events[1]
	if len(uri) != wantURILen {
		t.Errorf("makeEvents(%v)[1] = %v, want length %d", e, evtpb.Events[1], wantURILen)
	}
}
