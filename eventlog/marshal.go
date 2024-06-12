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
)

// Marshallable is an interface for writing an object as a stream of bytes to a writer.
type Marshallable interface {
	Marshal(io.Writer) error
}

// Marshal writes an array of bytes no longer than 255 entries with an initial byte noting
// the array length, and then each byte of the array afterwards.
func (b *ByteSizedCStr) Marshal(w io.Writer) error {
	data := []byte(b.Data + "\x00")
	if len(data) > 255 {
		return fmt.Errorf("data is too long for ByteSizedCStr: %d", len(data))
	}
	size := byte(len(data))
	return writeSizedArray(w, size, data)
}

// Marshal writes an array of bytes with a initial 4 bytes in little endian noting
// the array length, and then each byte of the array afterwards.
func (b *Uint32SizedArray) Marshal(w io.Writer) error {
	size := uint32(len(b.Data))
	return writeSizedArray(w, size, b.Data)
}

func writeSizedArray(w io.Writer, size any, data []byte) error {
	var isize int
	switch s := size.(type) {
	case byte:
		isize = int(s)
	case uint32:
		isize = int(s)
	default:
		return fmt.Errorf("unsupported array size type %T", size)
	}

	if err := binary.Write(w, binary.LittleEndian, size); err != nil {
		return fmt.Errorf("failed to write array size as %T: %v", size, err)
	}
	if n, err := w.Write(data); err != nil || n != isize {
		return fmt.Errorf("failed to write array (wrote %d bytes): %v", n, err)
	}
	return nil
}

func littleWrite(w io.Writer, field string, data any) (err error) {
	m, ok := data.(Marshallable)
	if ok {
		err = m.Marshal(w)
	} else {
		err = binary.Write(w, binary.LittleEndian, data)
	}
	if err != nil {
		return fmt.Errorf("failed to write %s as %T: %v", field, data, err)
	}
	return nil
}

// Marshal writes an EFI_GUID field.
func (g *EfiGUID) Marshal(w io.Writer) error {
	var efiguid [16]byte
	oabi.PutUUID(efiguid[:], g.UUID)
	if i, err := w.Write(efiguid[:]); err != nil || i != 16 {
		return fmt.Errorf("failed to write EFI_GUID (wrote %d bytes): %w", i, err)
	}
	return nil
}

// Marshal writes a uint32 sized array of T to the given writer.
func (d *Uint32SizedArrayT[T]) Marshal(w io.Writer) error {
	size := uint32(len(d.Array))
	if err := binary.Write(w, binary.LittleEndian, size); err != nil {
		return fmt.Errorf("failed to write uint32 sized array size: %v", err)
	}
	for i, e := range d.Array {
		if err := e.Marshal(w); err != nil {
			return fmt.Errorf("could not marshal element %d: %v", i, err)
		}
	}
	return nil
}
