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
	"crypto"
	"fmt"
	"io"
)

const (
	tpmAlgError  = 0x0000
	tpmAlgSHA1   = 0x0004
	tpmAlgSHA256 = 0x000B
	tpmAlgSHA384 = 0x000C

	// EvNoAction is an EventType indicating the event is not measured to any PCR.
	EvNoAction = 3
)

var tpmAlgoSize = map[uint16]int{
	tpmAlgSHA1:   crypto.SHA1.Size(),
	tpmAlgSHA256: crypto.SHA256.Size(),
	tpmAlgSHA384: crypto.SHA384.Size(),
}

// TaggedDigest represents a digest interpreted as tagged by the TPM_ALG_ID.
type TaggedDigest struct {
	AlgID  uint16
	Digest []byte
}

// Unmarshal populates the self TaggedDigest from the given reader.
func (d *TaggedDigest) Unmarshal(r io.Reader) error {
	if err := littleRead(r, "AlgID", &d.AlgID); err != nil {
		return err
	}
	algSize, ok := tpmAlgoSize[d.AlgID]
	if !ok {
		return fmt.Errorf("unsupported digest algorithm %d", d.AlgID)
	}
	d.Digest = make([]byte, algSize)
	if n, err := r.Read(d.Digest); err != nil || n != int(algSize) {
		return fmt.Errorf("failed to read digest sized %d (read %d bytes): %v", algSize, n, err)
	}
	return nil
}

// Create creates a TaggedDigest.
func (*TaggedDigest) Create() Unmarshallable {
	return &TaggedDigest{}
}
