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

// Package gcetcbendorsement provides functions for interpreting VMLaunchEndorsements.
package gcetcbendorsement

import (
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"os"
	"time"

	"google.golang.org/protobuf/proto"

	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	fmpb "google.golang.org/protobuf/types/known/fieldmaskpb"
)

var (
	// ErrNoInspect is returned when no Inspect is found in the context.
	ErrNoInspect = errors.New("no Inspect found in context")
)

// Inspect represents arguments to the VMLaunchEndorsement inspect command.
type Inspect struct {
	Writer TerminalWriter
	Form   BytesForm
}

type inspectKeyType struct{}

var inspectKey inspectKeyType

// WithInspect returns a context with the inspect options added.
func WithInspect(ctx context.Context, i *Inspect) context.Context {
	return context.WithValue(ctx, inspectKey, i)
}

func inspectFrom(ctx context.Context) (*Inspect, error) {
	i, ok := ctx.Value(inspectKey).(*Inspect)
	if !ok {
		return nil, ErrNoInspect
	}
	if i.Writer == nil {
		i.Writer = OSFileWriter{os.Stdout}
	}
	return i, nil
}

// InspectSignature outputs the signature of the endorsement.
func InspectSignature(ctx context.Context, endorsement *epb.VMLaunchEndorsement) error {
	i, err := inspectFrom(ctx)
	if err != nil {
		return err
	}
	return WriteBytesForm(endorsement.GetSignature(), i.Form, i.Writer)
}

// InspectPayload outputs the signature of the endorsement.
func InspectPayload(ctx context.Context, endorsement *epb.VMLaunchEndorsement) error {
	i, err := inspectFrom(ctx)
	if err != nil {
		return err
	}
	return WriteBytesForm(endorsement.SerializedUefiGolden, i.Form, i.Writer)
}

// InspectMask outputs the masked fields of the endorsement's golden measurement.
func InspectMask(ctx context.Context, endorsement *epb.VMLaunchEndorsement, mask *fmpb.FieldMask) error {
	i, err := inspectFrom(ctx)
	if err != nil {
		return err
	}
	opts := &MaskOptions{
		BytesForm: i.Form,
		Writer:    i.Writer,
		PathRenderer: map[string]FieldRenderer{
			"timestamp": RenderTimestamp(time.RFC3339),
		},
	}
	golden := &epb.VMGoldenMeasurement{}
	if err := proto.Unmarshal(endorsement.SerializedUefiGolden, golden); err != nil {
		return fmt.Errorf("failed to unmarshal VMGoldenMeasurement: %v", err)
	}

	return opts.Mask(golden, mask)
}
