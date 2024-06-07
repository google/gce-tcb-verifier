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
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/google/gce-tcb-verifier/eventlog"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/gce-tcb-verifier/verify"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

const (
	googleEfiVariable  = "a2858e46-a37f-456a-8c79-0c1fe48b65ff"
	sp800155Variable   = "FirmwareRIM"  // defined only for test comparison with rimVar
	googleID           = 11129          // IANA PEN
	googleManufacturer = "Google, Inc." // IANA PEN text
	platformModel      = "Google Compute Engine"
)

var (
	rimVar = []byte{
		0x46, 0x8e, 0x85, 0xa2, 0x7f, 0xa3, 0x6a, 0x45, 0x8c, 0x79, 0x0c, 0x1f, 0xe4, 0x8b, 0x65, 0xff,
		'F', 0, 'i', 0, 'r', 0, 'm', 0, 'w', 0, 'a', 0, 'r', 0, 'e', 0,
		'R', 0, 'I', 0, 'M', 0, 0, 0,
	}
)

func googleSp800155Event(rimGUID eventlog.EfiGUID, locType uint32, loc []byte) *eventlog.SP800155Event3 {
	return &eventlog.SP800155Event3{
		PlatformManufacturerID:  11129,
		ReferenceManifestGUID:   rimGUID,
		PlatformManufacturerStr: eventlog.ByteSizedArray{Data: []byte(googleManufacturer)},
		PlatformModel:           eventlog.ByteSizedArray{Data: []byte(platformModel)},
		FirmwareManufacturerStr: eventlog.ByteSizedArray{Data: []byte(googleManufacturer)},
		FirmwareManufacturerID:  11129,
		RIMLocatorType:          locType,
		RIMLocator:              eventlog.Uint32SizedArray{Data: loc},
	}
}

// An SP800155 event is stored in a HOB, which has a maximum size of UINT16 bytes including headers.
func marshalUint16Str(data []byte) []byte {
	return append(binary.LittleEndian.AppendUint16(nil, uint16(len(data))), data...)
}

func varEvent(rimGUID eventlog.EfiGUID) ([]byte, error) {
	result, err := googleSp800155Event(rimGUID, eventlog.RIMLocationVariable, rimVar).MarshalToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal UEFI variable SP800155 event: %v", err)
	}
	return marshalUint16Str(result), nil
}

func uriEvent(rimGUID eventlog.EfiGUID, digest []byte) ([]byte, error) {
	// This will need to not be hardcoded when we're signing multiple builds at a time, but for now
	// this works.
	obj := fmt.Sprintf("ovmf_x64_csm/%s.fd.signed", hex.EncodeToString(digest))
	result, err := googleSp800155Event(rimGUID, eventlog.RIMLocationURI,
		[]byte(verify.GCETcbURL(obj))).MarshalToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal URI SP800155 event: %v", err)
	}
	return marshalUint16Str(result), nil
}

// makeEvents returns the boot service UEFI variable contents the firmware will use to populate the
// PEI HOB list with Tcg800155PlatformIdEvents
func makeEvents(random io.Reader, endorsement *epb.VMLaunchEndorsement) ([]byte, error) {
	golden := &epb.VMGoldenMeasurement{}
	// error not checked since it has been deserialized before getting here.
	proto.Unmarshal(endorsement.GetSerializedUefiGolden(), golden)
	rimUUID, err := uuid.NewRandomFromReader(random)
	if err != nil {
		return nil, fmt.Errorf("failed to create RIM UUID: %v", err)
	}
	rimGUID := eventlog.EfiGUID{UUID: rimUUID}
	// We create 2 events: point to the uefi variable and point to the URI.
	varEvt, err := varEvent(rimGUID)
	if err != nil {
		return nil, err
	}
	uriEvt, err := uriEvent(rimGUID, golden.GetDigest())
	if err != nil {
		return nil, err
	}
	return append(varEvt, uriEvt...), nil
}
