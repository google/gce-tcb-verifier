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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	// EventSignatureSize is the size of the signature header for a TCG event log's EventData payload.
	EventSignatureSize = 16
)

var (
	eventFactories = map[string]func() UnmarshallableFromBytes{
		hex.EncodeToString(TcgSP800155Event3Signature[:]): func() UnmarshallableFromBytes { return &SP800155Event3{} },
	}
)

// TCGEventData represents data that may be in an event log's EventData payload. Expects the input
// data to have a 16 byte header specifying the event type.
type TCGEventData struct {
	Event UnmarshallableFromBytes
}

// UnknownEvent is a catch-all for EventData with unknown signature.
type UnknownEvent struct {
	Data []byte
}

// UnmarshalFromBytes stores the given data is the object's representation.
func (e *UnknownEvent) UnmarshalFromBytes(data []byte) error {
	e.Data = data
	return nil
}

// UnmarshallableFromBytes is an interface for populating the object by interpreting all given
// bytes as representing the object.
type UnmarshallableFromBytes interface {
	// UnmarshalFromBytes populates the current object from the totality of the given data or errors.
	UnmarshalFromBytes(data []byte) error
}

// Unmarshal reads a Uint32SizedUnmarshallable from the given reader.
func (d *TCGEventData) Unmarshal(r io.Reader) error {
	size := uint32(0)
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		return err
	}
	chunk := make([]byte, size)
	if n, err := r.Read(chunk); err != nil || uint32(n) != size {
		return fmt.Errorf("failed to read TCGEventData sized %d (read %d bytes): %w", size, n, err)
	}
	if size >= EventSignatureSize {
		signature := chunk[:EventSignatureSize]
		signatureKey := hex.EncodeToString(signature)
		factory, ok := eventFactories[signatureKey]
		if !ok {
			d.Event = &UnknownEvent{Data: chunk}
			return nil
		}
		d.Event = factory()
		d.Event.UnmarshalFromBytes(chunk[EventSignatureSize:])
	} else {
		d.Event = &UnknownEvent{Data: chunk}
	}
	return nil
}

// Create creates a TCGEventData.
func (*TCGEventData) Create() Unmarshallable {
	return &TCGEventData{}
}

// TCGPCClientPCREvent represents a TCG_PCClientPCREvent structure as specified in the PC Client
// Platform Firmware Profile.
type TCGPCClientPCREvent struct {
	PCRIndex   uint32
	EventType  uint32
	SHA1Digest [20]byte
	EventData  TCGEventData
}

// Unmarshal reads a TCGPCClientPCREvent from the given reader.
func (e *TCGPCClientPCREvent) Unmarshal(r io.Reader) error {
	if err := littleRead(r, "PCRIndex", &e.PCRIndex); err != nil {
		return err
	}
	if err := littleRead(r, "EventType", &e.EventType); err != nil {
		return err
	}
	if i, err := r.Read(e.SHA1Digest[:]); err != nil || i != 20 {
		return fmt.Errorf("failed to read SHA1Digest (read %d bytes): %w", i, err)
	}
	if err := littleRead(r, "EventData", &e.EventData); err != nil {
		return err
	}
	return nil
}

// Create creates a TCGPCClientPCREvent.
func (*TCGPCClientPCREvent) Create() Unmarshallable {
	return &TCGPCClientPCREvent{}
}

// TCGPCREvent2 represents a TCG_PCR_EVENT2 structure as specified in the PC Client Platform
// Firmware Profile.
type TCGPCREvent2 struct {
	PCRIndex  uint32
	EventType uint32
	Digests   Uint32SizedArrayT[*TaggedDigest]
	EventData TCGEventData
}

// Unmarshal reads a TCGPCREvent2 from the given reader.
func (e *TCGPCREvent2) Unmarshal(r io.Reader) error {
	if err := littleRead(r, "PCRIndex", &e.PCRIndex); err != nil {
		return err
	}
	if err := littleRead(r, "EventType", &e.EventType); err != nil {
		return err
	}
	if err := littleRead(r, "Digests", &e.Digests); err != nil {
		return err
	}
	if err := littleRead(r, "EventData", &e.EventData); err != nil {
		return err
	}
	return nil
}

// Create creates a TCGPCREvent2.
func (*TCGPCREvent2) Create() Unmarshallable {
	return &TCGPCREvent2{}
}

// CryptoAgileLog represents events parsed from a TCG crypto agile log formatted document.
type CryptoAgileLog struct {
	Header TCGPCClientPCREvent
	Events []*TCGPCREvent2
}

// Unmarshal reads a CryptoAgileLog from the given reader.
func (cel *CryptoAgileLog) Unmarshal(r io.Reader) error {
	if err := littleRead(r, "Header", &cel.Header); err != nil {
		return err
	}
	for {
		evt := &TCGPCREvent2{}
		if err := littleRead(r, "Event", evt); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		cel.Events = append(cel.Events, evt)
	}
}
