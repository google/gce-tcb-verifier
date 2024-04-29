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

// Package eventlog provides functions for reading PC Client event logs and various EventData they
// can carry.
package eventlog

import (
	"bytes"
	"fmt"
)

const (
	// RIMLocationRaw specifies that the location data is the data itself.
	RIMLocationRaw uint32 = iota
	// RIMLocationURI specifies that the location data is a URI for where to fetch the data.
	RIMLocationURI
	// RIMLocationLocal specifies that the location data is a local UEFI device path.
	RIMLocationLocal
	// RIMLocationVariable specifies that the location data is a UEFI variable name in 16-byte EFIGUID
	// followed by '\0\0'-terminated CHAR16 string of the variable name.
	RIMLocationVariable
)

var (
	// TcgSP800155Event3Signature is the Canonical Event Log event signature for an unmeasured
	// informational event that directs the reader to reference measurements for the firmware and
	// platform.
	TcgSP800155Event3Signature = [...]byte{
		'S', 'P', '8', '0', '0', '-', '1', '5', '5', ' ', 'E', 'v', 'e', 'n', 't', '3'}
)

// SP800155Event3 represents a TCG SP 800-155 Event3 event specified in the PC Client Platform
// Firmware Profile.
type SP800155Event3 struct {
	PlatformManufacturerID  uint32
	ReferenceManifestGUID   EfiGUID
	PlatformManufacturerStr ByteSizedArray
	PlatformModel           ByteSizedArray
	PlatformVersion         ByteSizedArray
	FirmwareManufacturerStr ByteSizedArray
	FirmwareManufacturerID  uint32
	FirmwareVersion         ByteSizedArray
	RIMLocatorType          uint32
	RIMLocator              Uint32SizedArray
	PlatformCertLocatorType uint32
	PlatformCertLocator     Uint32SizedArray
}

// UnmarshalFromBytes reads a TCG SP 800-155 Event3 event from the whole of the input slice.
func (evt *SP800155Event3) UnmarshalFromBytes(data []byte) error {
	r := bytes.NewBuffer(data)
	if err := littleRead(r, "PlatformManufacturerID", &evt.PlatformManufacturerID); err != nil {
		return err
	}
	if err := littleRead(r, "ReferenceManifestGuid", &evt.ReferenceManifestGUID); err != nil {
		return err
	}
	if err := littleRead(r, "PlatformManufacturerStr", &evt.PlatformManufacturerStr); err != nil {
		return err
	}
	if err := littleRead(r, "PlatformModel", &evt.PlatformModel); err != nil {
		return err
	}
	if err := littleRead(r, "PlatformVersion", &evt.PlatformVersion); err != nil {
		return err
	}
	if err := littleRead(r, "FirmwareManufacturerStr", &evt.FirmwareManufacturerStr); err != nil {
		return err
	}
	if err := littleRead(r, "FirmwareManufacturerID", &evt.FirmwareManufacturerID); err != nil {
		return err
	}
	if err := littleRead(r, "FirmwareVersion", &evt.FirmwareVersion); err != nil {
		return err
	}
	if err := littleRead(r, "RIMLocatorType", &evt.RIMLocatorType); err != nil {
		return err
	}
	if err := littleRead(r, "RIMLocator", &evt.RIMLocator); err != nil {
		return err
	}
	if err := littleRead(r, "PlatformCertLocatorType", &evt.PlatformCertLocatorType); err != nil {
		return err
	}
	if err := littleRead(r, "PlatformCertLocator", &evt.PlatformCertLocator); err != nil {
		return err
	}
	if r.Len() > 0 {
		return fmt.Errorf("%d bytes remaining of SP800155Event3. Want EOF", r.Len())
	}
	return nil
}
