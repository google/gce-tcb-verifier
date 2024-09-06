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
	tcpb "github.com/google/go-tdx-guest/proto/checkconfig"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

var (
	errNoTdxPolicy  = errors.New("tdx command not found in context")
	errNoTdxCommand = errors.New("tdx sub-command must be used")
)

type tdxCommand struct {
	overwrite bool
	base      string
	ramGiB    int
	// derived
	basePolicy *tcpb.Policy
}

type tdxKeyType struct{}

var tdxKey tdxKeyType

type tdxPolicyCommand struct {
	out     string
	outform string
	// derived
	textproto   bool
	bytesform   gcetcbendorsement.BytesForm
	endorsement *epb.VMLaunchEndorsement
}

type tdxValidateCommand struct {
	endorsementPath string
	root            string
	// derived
	content     []byte
	endorsement *epb.VMLaunchEndorsement
}

func tdxFrom(ctx context.Context) (*tdxCommand, error) {
	if c, ok := ctx.Value(tdxKey).(*tdxCommand); ok {
		return c, nil
	}
	return nil, errNoTdxPolicy
}

func (c *tdxPolicyCommand) persistentPreRunE(cmd *cobra.Command, args []string) (err error) {
	// Check positional argument
	if len(args) != 1 {
		return fmt.Errorf("tdx-policy expects exactly one positional argument, got %d", len(args))
	}
	if c.outform == "textproto" {
		c.textproto = true
	} else if c.bytesform, err = gcetcbendorsement.ParseBytesForm(c.outform); err != nil {
		return err
	}
	endorsement := args[0]
	c.endorsement = &epb.VMLaunchEndorsement{}
	return ReadProto(cmd.Context(), endorsement, c.endorsement)
}

func (c *tdxPolicyCommand) runE(cmd *cobra.Command, args []string) error {
	backend, err := backendFrom(cmd.Context())
	if err != nil {
		return err
	}
	s, err := tdxFrom(cmd.Context())
	if err != nil {
		return err
	}
	policy, err := gcetcbendorsement.TdxPolicy(cmd.Context(), c.endorsement, &gcetcbendorsement.TdxPolicyOptions{
		Base:      s.basePolicy,
		Overwrite: s.overwrite,
		RAMGiB:    s.ramGiB,
	})
	if err != nil {
		return fmt.Errorf("failed to generate tdx policy: %v", err)
	}
	out, cleanup, err := backend.IO.Create(c.out)
	if err != nil {
		return err
	}
	defer cleanup()
	if c.textproto || (c.bytesform == gcetcbendorsement.BytesAuto && out.IsTerminal()) {
		text, err := prototext.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(policy)
		if err != nil {
			return fmt.Errorf("could not marshal policy as textproto: %v", err)
		}
		_, err = out.Write(text)
		return err
	}
	bin, err := proto.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal tdx policy: %v", err)
	}
	return gcetcbendorsement.WriteBytesForm(bin, c.bytesform, out)
}

func (c *tdxValidateCommand) persistentPreRunE(cmd *cobra.Command, args []string) error {
	backend, err := backendFrom(cmd.Context())
	if err != nil {
		return err
	}
	if len(args) != 1 {
		return fmt.Errorf("tdx validate expects exactly one positional argument, got %d", len(args))
	}
	attestation := args[0]
	content, err := backend.IO.ReadFile(attestation)
	if err != nil {
		return fmt.Errorf("failed to read attestation file %q: %v", attestation, err)
	}
	c.content = content
	if c.endorsementPath != "" {
		c.endorsement = &epb.VMLaunchEndorsement{}
		return ReadProto(cmd.Context(), c.endorsementPath, c.endorsement)
	}
	return nil
}

func (c *tdxValidateCommand) runE(cmd *cobra.Command, args []string) error {
	backend, err := backendFrom(cmd.Context())
	if err != nil {
		return err
	}
	s, err := tdxFrom(cmd.Context())
	if err != nil {
		return err
	}
	rot, err := rootOfTrust(cmd.Context(), c.root)
	if err != nil {
		return err
	}

	return gcetcbendorsement.TdxValidate(cmd.Context(), c.content,
		&gcetcbendorsement.TdxValidateOptions{
			Now:          backend.Now,
			Getter:       backend.Getter,
			Endorsement:  c.endorsement,
			Overwrite:    s.overwrite,
			BasePolicy:   s.basePolicy,
			RootsOfTrust: rot,
		})
}

func makeTdxPolicyCommand(ctx context.Context) *cobra.Command {
	c := &tdxPolicyCommand{}
	cmd := &cobra.Command{
		Use: "policy PATH [--out=PATH] [--outform=textproto|bin|hex|base64|auto]",
		Long: `Creates a go-tdx-guest validation policy to fit the firmware endorsement.

The mandatory PATH must be to a binary serialized VMLaunchEndorsement.
`,
		PersistentPreRunE: c.persistentPreRunE,
		RunE:              c.runE,
	}
	cmd.Flags().StringVar(&c.out, "out", "-", "Path to output serialized checkconfig.Policy. "+
		"Default - for stdout.")
	cmd.Flags().StringVar(&c.outform, "outform", "auto", outformUsage)
	cmd.SetContext(ctx)
	return cmd
}

func makeTdxValidateCommand(ctx context.Context) *cobra.Command {
	c := &tdxValidateCommand{}
	cmd := &cobra.Command{
		Use: "validate PATH [--endorsement=PATH] ",
		Long: `Validates a TDX quote against its firmware endorsement.

The mandatory PATH must be to an attestation in one of the following formats:` +
			attestationFormatsUsage,
		PersistentPreRunE: c.persistentPreRunE,
		RunE:              c.runE,
	}
	cmd.Flags().StringVar(&c.endorsementPath, "endorsement", "",
		"The path to an endorsement file. Overrides what could be extracted from the attestation.")
	cmd.Flags().StringVar(&c.root, "root_cert", "", "The root certificate for endorsements.")
	cmd.SetContext(ctx)
	return cmd
}

func (c *tdxCommand) persistentPreRunE(cmd *cobra.Command, _ []string) error {
	// Check -base flag
	if c.base != "" {
		c.basePolicy = &tcpb.Policy{}
		return ReadProto(cmd.Context(), c.base, c.basePolicy)
	}
	return nil
}

func makeTdxCommand(ctx0 context.Context) *cobra.Command {
	c := &tdxCommand{}
	cmd := &cobra.Command{
		Use:               "tdx CMD [-base=PATH] [-overwrite] [-ram_gib=#]",
		Long:              `Parent to TDX subcommands that share configuration flags.`,
		PersistentPreRunE: c.persistentPreRunE,
		RunE: func(*cobra.Command, []string) error {
			return errNoTdxCommand
		},
	}
	cmd.PersistentFlags().BoolVar(&c.overwrite, "overwrite", false,
		"If false, it is an error for populated base policy fields to be overwritten.")
	cmd.PersistentFlags().StringVar(&c.base, "base", "", "Path to base go-tdx-guest checkconfig.Policy.")
	cmd.PersistentFlags().IntVar(&c.ramGiB, "ram_gib", 0, "Amount of RAM created with. If 0, considers all endorsed sizes.")
	ctx := context.WithValue(ctx0, tdxKey, c)
	cmd.AddCommand(makeTdxValidateCommand(ctx))
	cmd.AddCommand(makeTdxPolicyCommand(ctx))
	cmd.SetContext(ctx)
	return cmd
}
