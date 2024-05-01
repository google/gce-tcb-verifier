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
	"fmt"
	"io"

	oabi "github.com/google/gce-tcb-verifier/ovmf/abi"
	"github.com/google/uuid"
)

// Serializable is an interface for populating the object by unmarshalling data, or marshalling
// the object to bytes.
type Serializable interface {
	Unmarshal(io.Reader) error
	Marshal(io.Writer) error
	Create() Serializable
}

// Unmarshallable is an interface for populating the object by unmarshalling data.
type Unmarshallable interface {
	Unmarshal(io.Reader) error
}

// ByteSizedArray represents an array of bytes no longer than 255 entries that is serialized first
// with a single byte specifying the array size.
type ByteSizedArray struct {
	Data []byte
}

// Unmarshal reads an array of bytes no longer than 255 entries that is serialized first
// with a single byte specifying the array size.
func (b *ByteSizedArray) Unmarshal(r io.Reader) error {
	size := byte(0)
	return readSizedArray(r, &size, &b.Data)
}

// Create creates a new ByteSizedArray.
func (*ByteSizedArray) Create() Serializable {
	return &ByteSizedArray{}
}

// Uint32SizedArray represents an array of bytes no longer than 2^32 - 1 entries that is serialized
// first with a little endian uint32 specifying the array size.
type Uint32SizedArray struct {
	Data []byte
}

// Create creates a new Uint32SizedArray.
func (*Uint32SizedArray) Create() Serializable {
	return &Uint32SizedArray{}
}

// Unmarshal reads an array of bytes no longer than 2^32 - 1 entries that is serialized
// first with a little endian uint32 specifying the array size.
func (b *Uint32SizedArray) Unmarshal(r io.Reader) error {
	size := uint32(0)
	return readSizedArray(r, &size, &b.Data)
}

func makeSized[T any](size any) ([]T, error) {
	switch s := size.(type) {
	case *byte:
		return make([]T, *s), nil
	case *uint32:
		return make([]T, *s), nil
	default:
		return nil, fmt.Errorf("unsupported array size type %T", size)
	}
}

// Uint32SizedArrayT represents a uint32 sized array of a given type, with elements that are
// serializable.
type Uint32SizedArrayT[T Serializable] struct {
	Array []T
}

// Create creates a Uint32SizedArrayT.
func (*Uint32SizedArrayT[T]) Create() Serializable {
	return &Uint32SizedArrayT[T]{}
}

// Unmarshal reads a uint32 sized array of T into a Uint32SizedArrayT[T] from the given reader.
func (d *Uint32SizedArrayT[T]) Unmarshal(r io.Reader) error {
	size := uint32(0)
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		return fmt.Errorf("failed to read Uint32SizedArrayT %T sized %d: %v", []T{}, size, err)
	}
	d.Array = make([]T, size)
	for i := range d.Array {
		d.Array[i] = d.Array[i].Create().(T)
		if err := d.Array[i].Unmarshal(r); err != nil {
			return fmt.Errorf("failed to unmarshal %T element %d: %v", []T{}, i, err)
		}
	}
	return nil
}

func readSizedArray(r io.Reader, size any, data *[]byte) error {
	if err := binary.Read(r, binary.LittleEndian, size); err != nil {
		return fmt.Errorf("failed to read array size as %T: %w", size, err)
	}
	result, err := makeSized[byte](size)
	if err != nil {
		return err
	}
	if _, err := r.Read(result); err != nil {
		return err
	}
	*data = result
	return nil
}

// EfiGUID represents a UUID that is marshalled as an EFI_GUID.
type EfiGUID struct {
	UUID uuid.UUID
}

func littleRead(r io.Reader, field string, data any) (err error) {
	um, ok := data.(Unmarshallable)
	if ok {
		err = um.Unmarshal(r)
	} else {
		err = binary.Read(r, binary.LittleEndian, data)
	}
	if err != nil {
		return fmt.Errorf("failed to read %s as %T: %w", field, data, err)
	}
	return nil
}

// Unmarshal reads an EFI_GUID field.
func (g *EfiGUID) Unmarshal(r io.Reader) error {
	var efiguid [16]byte
	if i, err := r.Read(efiguid[:]); err != nil || i != 16 {
		return fmt.Errorf("failed to read EFI_GUID (read %d bytes): %w", i, err)
	}
	result, _ := oabi.FromEFIGUID(efiguid[:])
	g.UUID = result
	return nil
}

// Create creates a new EfiGUID.
func (*EfiGUID) Create() Serializable {
	return &EfiGUID{}
}
