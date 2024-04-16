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

package gcetcbendorsement

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/gce-tcb-verifier/gcetcbendorsement/parsepath/parsepath"
	"github.com/google/uuid"
	"golang.org/x/term"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protopath"
	"google.golang.org/protobuf/reflect/protoreflect"
	fpb "google.golang.org/protobuf/types/known/fieldmaskpb"
	tpb "google.golang.org/protobuf/types/known/timestamppb"
)

// BytesForm is the type of form to use for rendering `bytes` fields.
type BytesForm int

const (
	// BytesRaw instructs Mask to write `bytes` fields as a raw string.
	BytesRaw BytesForm = iota
	// BytesHex  instructs Mask to write `bytes` fields with a hex-encoded string.
	BytesHex
	// BytesHexGuidify instructs Mask to write `bytes` fields with a hex-encoded string unless 16
	// bytes long. If 16 bytes long, render as a GUID.
	BytesHexGuidify
	// BytesBase64  instructs Mask to write `bytes` fields with a base64-encoded string.
	BytesBase64
	// BytesAuto is instructs Mask to write `bytes` fields in a form dependent on the writer. If the
	// writer is terminal, then it uses a base64-encoded string. If it's not a terminal, it uses raw
	// binary.
	BytesAuto
)

// TerminalWriter is an io.Writer that can determine if it's a terminal or not.
type TerminalWriter interface {
	// Write writes len(p) bytes from p to the underlying data stream.
	// It returns the number of bytes written from p (0 <= n <= len(p))
	// and any error encountered that caused the write to stop early.
	// Write must return a non-nil error if it returns n < len(p).
	// Write must not modify the slice data, even temporarily.
	Write([]byte) (int, error)
	// IsTerminal returns true if the writer is a terminal.
	IsTerminal() bool
}

// NonterminalWriter wraps the io.Writer interface while also making IsTerminal() always return
// false.
type NonterminalWriter struct{ Writer io.Writer }

func (w NonterminalWriter) Write(p []byte) (int, error) { return w.Writer.Write(p) }

// IsTerminal returns false.
func (w NonterminalWriter) IsTerminal() bool { return false }

// OSFileWriter wraps the os.File interface while also making IsTerminal() return whether the file's
// encapsulated file descriptor is a TTY.
type OSFileWriter struct{ File *os.File }

func (w OSFileWriter) Write(p []byte) (int, error) { return w.File.Write(p) }

// IsTerminal returns whether the file's encapsulated file descriptor is a TTY.
func (w OSFileWriter) IsTerminal() bool { return term.IsTerminal(int(w.File.Fd())) }

func writeBase64(bytes []byte, w TerminalWriter) error {
	enc := base64.NewEncoder(base64.StdEncoding, w)
	_, err := enc.Write(bytes)
	enc.Close()
	return err
}

// WriteBytesForm writes bytes according to a BytesForm to the given TerminalWriter.
func WriteBytesForm(bytes []byte, form BytesForm, w TerminalWriter) error {
	switch form {
	case BytesRaw:
		_, err := w.Write(bytes)
		return err
	case BytesHex:
		_, err := hex.NewEncoder(w).Write(bytes)
		return err
	case BytesHexGuidify:
		if len(bytes) != 16 {
			_, err := hex.NewEncoder(w).Write(bytes)
			return err
		}
		GUID, err := uuid.FromBytes(bytes)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(GUID.String()))
		return err
	case BytesBase64:
		return writeBase64(bytes, w)
	case BytesAuto:
		if w.IsTerminal() {
			return writeBase64(bytes, w)
		}
		_, err := w.Write(bytes)
		return err
	}
	return nil
}

// ParseBytesForm parses a BytesForm option name to the corresponding constant.
func ParseBytesForm(form string) (BytesForm, error) {
	switch form {
	case "bin":
		return BytesRaw, nil
	case "hex":
		return BytesHex, nil
	case "base64":
		return BytesBase64, nil
	case "auto":
		return BytesAuto, nil
	default:
		return BytesRaw, fmt.Errorf("unknown bytes form %q. Must be one of bin|hex|base64|auto", form)
	}
}

type protopathIndex struct {
	Step  protopath.Step
	Value protoreflect.Value
}

// FieldRenderer is called on fields that are present at the path this function is mapped to.
type FieldRenderer func(*MaskOptions, protopathIndex) error

// MaskOptions contains options for rendering named fields in a VMGoldenMeasurement.
type MaskOptions struct {
	BytesForm    BytesForm
	Writer       TerminalWriter
	PathRenderer map[string]FieldRenderer
}

// RenderTimestamp return a FieldRenderer for a Timestamp message using a given Golang time format
// string.
func RenderTimestamp(timeFormat string) FieldRenderer {
	return func(opts *MaskOptions, t protopathIndex) error {
		v := t.Value.Interface()
		tm, ok := v.(protoreflect.Message)
		if !ok {
			return fmt.Errorf("unexpected type %T. Want protoreflect.Message", v)
		}
		ts, ok := tm.Interface().(*tpb.Timestamp)
		if !ok {
			return fmt.Errorf("unexpected type %T. Want *tpb.Timestamp", tm)
		}
		timet := time.Unix(ts.GetSeconds(), int64(ts.GetNanos()))
		_, err := opts.Writer.Write([]byte(fmt.Sprintf("%s", timet.Format(timeFormat))))
		return err
	}
}

func (opts *MaskOptions) marshal(v protopathIndex) error {
	genericWrite := func(value any) error {
		if b, ok := value.([]byte); ok {
			return WriteBytesForm(b, opts.BytesForm, opts.Writer)
		}

		_, err := opts.Writer.Write([]byte(fmt.Sprintf("%v", value)))
		return err
	}

	switch t := v.Value.Interface().(type) {
	case []uint8:
		return WriteBytesForm(t, opts.BytesForm, opts.Writer)
	case protoreflect.Message:
		out, err := prototext.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(t.Interface())
		if err != nil {
			return err
		}
		_, err = opts.Writer.Write(out)
		return err
	default:
		if v.Step.Kind() == protopath.FieldAccessStep {
			// This could be a map or a list, not a message.
			if v.Step.FieldDescriptor().IsMap() {
				first := true
				v.Value.Map().Range(func(k protoreflect.MapKey, v protoreflect.Value) bool {
					if !first {
						opts.Writer.Write([]byte{'\n'})
					}
					first = false
					opts.Writer.Write([]byte(fmt.Sprintf("%s: %s", k.String(), v.String())))
					return true
				})
				return nil
			}
			// There are no lists in the endorsement proto.
		}
		return genericWrite(t)
	}
}

// Mask writes `src` restricted to `mask` with `bytes` fields rendered with
// the given `form` in the opts.Writer.
func (opts *MaskOptions) Mask(src proto.Message, mask *fpb.FieldMask) error {
	if src == nil {
		return fmt.Errorf("src is nil")
	}
	if mask == nil {
		return fmt.Errorf("mask is nil")
	}
	reflmsg := src.ProtoReflect()
	descriptor := reflmsg.Descriptor()

	for i, path := range mask.GetPaths() {
		reflpath, err := parsepath.ParsePath(descriptor, path)
		if err != nil {
			// Error should not occur here as path has been validated above.
			return fmt.Errorf("error in parsing path %q: %v", path, err)
		}

		vs, err := parsepath.PathValues(reflpath, src)
		if err != nil {
			return fmt.Errorf("error in visiting path values %q: %v", path, err)
		}
		if i != 0 {
			if _, err := opts.Writer.Write([]byte{'\n'}); err != nil {
				return err
			}
		}

		if renderer, ok := opts.PathRenderer[path]; ok {
			if err := renderer(opts, vs.Index(-1)); err != nil {
				return err
			}
			continue
		}

		if err := opts.marshal(vs.Index(-1)); err != nil {
			return err
		}
	}
	return nil
}
