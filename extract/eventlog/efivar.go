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
	"fmt"
	"io"
	"os"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/google/uuid"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// VariableReader provides a method of reading UEFI variable contents given the
// vendor GUID and CHAR16 variable name. The UEFI specification states that strings
// are encoded in UCS-2.
type VariableReader interface {
	ReadVariable(guid uuid.UUID, name []uint8) ([]byte, error)
}

// EfiVarFSReader implements VariableReader for the Linux efivarfs interface to UEFI
// variables.
type EfiVarFSReader struct {
	// Root is the mount location of the efivarfs volume.
	Root string
}

// Returns an error if any rune of utf8encoding is unrepresentable in UCS-2.
// Uses the ucs2encoding for context in error messages.
func validateUCS2Codepoints(ucs2encoding, utf8encoding []byte) error {
	read := bytes.NewBuffer(utf8encoding)
	for {
		r, n, err := read.ReadRune()
		if err == io.EOF {
			break
		}
		// Bad encoding
		if r == 0xFFFD && n == 1 {
			return fmt.Errorf("could not decode UCS-2 name %v", ucs2encoding)
		}
		if r > 0xFFFF {
			return fmt.Errorf("codepoint 0x%x is unrepresentable in UCS-2", r)
		}
	}
	return nil
}

// ucs2toUTF8 translates a string in UCS-2 encoding to UTF-8 by first
// interpreting the string as UTF-16 and then rejecting runes unrepresentable
// in UCS-2, i.e., codepoints greater than 65535.
func ucs2toUTF8(name []uint8) (string, error) {
	e := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	utf8encoding, _, err := transform.Bytes(e.NewDecoder(), name)
	if err != nil {
		return "", fmt.Errorf("could not decode UCS-2: %v", err)
	}
	// Remove null terminator if one exists.
	if utf8encoding[len(utf8encoding)-1] == 0 {
		utf8encoding = utf8encoding[:len(utf8encoding)-1]
	}
	if err := validateUCS2Codepoints(name, utf8encoding); err != nil {
		return "", err
	}
	return string(utf8encoding), nil
}

func (r *EfiVarFSReader) varBasename(guid uuid.UUID, name []uint8) (string, error) {
	// Note that at time of writing, Linux does not correctly translate the UTF-8
	// path to UCS-2 VariableName when parsing the efivarfs path.
	basename, err := ucs2toUTF8(name)
	if err != nil {
		return "", err
	}
	path, err := securejoin.SecureJoin(r.Root, fmt.Sprintf("%s-%s", basename, guid))
	if err != nil {
		return "", fmt.Errorf("variable name evaluated to illegal path: %v", err)
	}
	return path, nil
}

// ReadVariable returns the contents of a UEFI variable using Linux's efivarfs volume
// represented in r.Root. The name is in UEFI-native UCS-2 encoding. We use the UTF-16
// decoder because UCS-2 and UTF-16 use the same encoding for code points representable
// in 16 bits.
func (r *EfiVarFSReader) ReadVariable(guid uuid.UUID, name []uint8) ([]byte, error) {
	path, err := r.varBasename(guid, name)
	if err != nil {
		return nil, err
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(contents) < 4 {
		return nil, fmt.Errorf("variable contents ill-formed. %v does not start with 4-byte attribute header", contents)
	}
	return contents[4:], nil
}

// MakeEfiVarFSReader returns a Linux efivarfs UEFI variable reader
func MakeEfiVarFSReader(root string) *EfiVarFSReader {
	return &EfiVarFSReader{Root: root}
}
