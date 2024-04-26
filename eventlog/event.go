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
	eventFactories = map[string]func() SerializableFromBytes{
		hex.EncodeToString(TcgSP800155Event3Signature[:]): func() SerializableFromBytes { return &SP800155Event3{} },
	}
)

// TCGEventData represents data that may be in an event log's EventData payload. Expects the input
// data to have a 16 byte header specifying the event type.
type TCGEventData struct {
	Event SerializableFromBytes
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

// MarshalToBytes returns the stored data.
func (e *UnknownEvent) MarshalToBytes() ([]byte, error) {
	return e.Data, nil
}

// SerializableFromBytes is an interface for populating the object by interpreting all given
// bytes as representing the object, and writing the object as a string of bytes.
type SerializableFromBytes interface {
	// UnmarshalFromBytes populates the current object from the totality of the given data or errors.
	UnmarshalFromBytes(data []byte) error
	// MarshalToBytes writes the object to a byte array, including its 16 byte signature.
	MarshalToBytes() ([]byte, error)
}

// Unmarshal reads a Uint32 sized, UnmarshallableToBytes from the given reader.
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

// Marshal write a TCGEventData to the given writer.
func (d *TCGEventData) Marshal(w io.Writer) error {
	if d.Event == nil {
		if err := binary.Write(w, binary.LittleEndian, uint32(0)); err != nil {
			return fmt.Errorf("could not write empty event size 0 as uint32: %v", err)
		}
		return nil
	}
	dat, err := d.Event.MarshalToBytes()
	if err != nil {
		return fmt.Errorf("could not marshal event: %v", err)
	}
	if err := binary.Write(w, binary.LittleEndian, uint32(len(dat))); err != nil {
		return fmt.Errorf("could not write event size as uint32: %v", err)
	}
	if n, err := w.Write(dat); err != nil || n != len(dat) {
		return fmt.Errorf("could not marshal event (wrote %d bytes): %v", n, err)
	}
	return nil
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

// Marshal writes a TCGPCClientPCREvent to the given writer.
func (e *TCGPCClientPCREvent) Marshal(w io.Writer) error {
	if err := littleWrite(w, "PCRIndex", e.PCRIndex); err != nil {
		return err
	}
	if err := littleWrite(w, "EventType", e.EventType); err != nil {
		return err
	}
	if i, err := w.Write(e.SHA1Digest[:]); err != nil || i != 20 {
		return fmt.Errorf("failed to write SHA1Digest (wrote %d bytes): %w", i, err)
	}
	if err := littleWrite(w, "EventData", &e.EventData); err != nil {
		return err
	}
	return nil
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

// Marshal writes a TCGPCREvent2 to the given writer.
func (e *TCGPCREvent2) Marshal(w io.Writer) error {
	if err := littleWrite(w, "PCRIndex", e.PCRIndex); err != nil {
		return err
	}
	if err := littleWrite(w, "EventType", e.EventType); err != nil {
		return err
	}
	if err := littleWrite(w, "Digests", &e.Digests); err != nil {
		return err
	}
	if err := littleWrite(w, "EventData", &e.EventData); err != nil {
		return err
	}
	return nil
}

// Create creates a TCGPCREvent2.
func (*TCGPCREvent2) Create() Serializable {
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

// Marshal writes a CryptoAgileLog to the given writer
func (cel *CryptoAgileLog) Marshal(w io.Writer) error {
	if err := littleWrite(w, "Header", &cel.Header); err != nil {
		return err
	}
	for i, evt := range cel.Events {
		if err := littleWrite(w, "Event", evt); err != nil {
			return fmt.Errorf("could not write event %d: %v", i, err)
		}
	}
	return nil
}
