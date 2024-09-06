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

package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/gce-tcb-verifier/gcetcbendorsement"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/spf13/cobra"
	fmpb "google.golang.org/protobuf/types/known/fieldmaskpb"
)

var (
	errNoInspect = errors.New("no inspectCommand in context")
)

type inspectCommand struct {
	output string
	form   string
	paths  []string
	// derived from flags and arguments
	endorsement *epb.VMLaunchEndorsement
	bytesForm   gcetcbendorsement.BytesForm
	out         gcetcbendorsement.TerminalWriter
	outDefer    func()
}

type inspectKeyType struct{}

var inspectKey inspectKeyType

type maskSubCommand struct {
	paths []string
}

func (m *maskSubCommand) runE(cmd *cobra.Command, args []string) error {
	inspect, ok := cmd.Context().Value(inspectKey).(*inspectCommand)
	if !ok {
		return errNoInspect
	}
	ctx := gcetcbendorsement.WithInspect(cmd.Context(), &gcetcbendorsement.Inspect{
		Writer: inspect.out,
		Form:   inspect.bytesForm,
	})
	defer inspect.outDefer()
	return gcetcbendorsement.InspectMask(ctx, inspect.endorsement, &fmpb.FieldMask{Paths: m.paths})
}

func (c *inspectCommand) persistentPreRunE(cmd *cobra.Command, args []string) error {
	backend, err := backendFrom(cmd.Context())
	if err != nil {
		return err
	}
	// Check positional arg
	if len(args) != 1 {
		return fmt.Errorf("inspect expects exactly one argument, got %d", len(args))
	}
	c.bytesForm, err = gcetcbendorsement.ParseBytesForm(c.form)
	if err != nil {
		return fmt.Errorf("failed to parse bytes form %q: %v", c.form, err)
	}
	endorsement := args[0]
	c.endorsement = &epb.VMLaunchEndorsement{}
	if err := ReadProto(cmd.Context(), endorsement, c.endorsement); err != nil {
		return err
	}
	c.out, c.outDefer, err = backend.IO.Create(c.output)
	return err
}

func makeSignatureCmd(ctx0 context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:  "signature FILE [options]",
		Long: `Outputs a GCE endorsement's signature.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			inspect, ok := cmd.Context().Value(inspectKey).(*inspectCommand)
			if !ok {
				return errNoInspect
			}
			ctx := gcetcbendorsement.WithInspect(cmd.Context(), &gcetcbendorsement.Inspect{
				Writer: inspect.out,
				Form:   inspect.bytesForm,
			})
			defer inspect.outDefer()
			return gcetcbendorsement.InspectSignature(ctx, inspect.endorsement)
		},
	}
	cmd.SetContext(ctx0)
	return cmd
}

func makePayloadCmd(ctx0 context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:  "payload FILE [options]",
		Long: `Outputs a GCE endorsement's payload.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			inspect, ok := cmd.Context().Value(inspectKey).(*inspectCommand)
			if !ok {
				return errNoInspect
			}
			ctx := gcetcbendorsement.WithInspect(cmd.Context(), &gcetcbendorsement.Inspect{
				Writer: inspect.out,
				Form:   inspect.bytesForm,
			})
			defer inspect.outDefer()
			return gcetcbendorsement.InspectPayload(ctx, inspect.endorsement)
		},
	}
	cmd.SetContext(ctx0)
	return cmd
}

func makeMaskCmd(ctx0 context.Context) *cobra.Command {
	m := &maskSubCommand{}
	cmd := &cobra.Command{
		Use:  "mask FILE [options]",
		Long: `Outputs field paths into a GCE endorsement's golden measurement.`,
		RunE: m.runE,
	}
	cmd.Flags().StringSliceVar(&m.paths, "path", nil,
		"Paths into the VMGoldenMeasurement to print on separate lines.")
	cmd.SetContext(ctx0)
	return cmd
}

func makeInspect(ctx0 context.Context) *cobra.Command {
	i := &inspectCommand{}
	cmd := &cobra.Command{
		Use:               "inspect CMD FILE [options]",
		Long:              `Outputs different aspects of the GCE endorsement.`,
		PersistentPreRunE: i.persistentPreRunE,
		Run:               func(cmd *cobra.Command, args []string) {},
	}
	cmd.PersistentFlags().StringVar(&i.output, "out", "-",
		"The output destination for the inspected endorsement. Default - for stdout.")
	cmd.PersistentFlags().StringVar(&i.form, "bytesform", "auto",
		"One of bin|hex|base64|auto. Output bytes fields as raw binary, encoded as hex, or base64. "+
			"Auto means the default is base64 if writing to a terminal, otherwise bin.")
	ctx := context.WithValue(ctx0, inspectKey, i)
	cmd.AddCommand(makeSignatureCmd(ctx))
	cmd.AddCommand(makePayloadCmd(ctx))
	cmd.AddCommand(makeMaskCmd(ctx))
	cmd.SetContext(ctx)
	return cmd
}
