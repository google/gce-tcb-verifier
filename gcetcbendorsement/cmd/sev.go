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

	"github.com/google/gce-tcb-verifier/extract"
	"github.com/google/gce-tcb-verifier/gcetcbendorsement"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	cpb "github.com/google/go-sev-guest/proto/check"
	tpmpb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

var (
	errNoSevPolicy  = errors.New("sev command not found in context")
	errNoSevCommand = errors.New("sev sub-command must be used")
)

type sevCommand struct {
	overwrite             bool
	base                  string
	launchVmsas           uint32
	allowUnspecifiedVmsas bool
	// derived
	basePolicy *cpb.Policy
}

type sevKeyType struct{}

var sevKey sevKeyType

type sevPolicyCommand struct {
	out     string
	outform string
	// derived
	textproto   bool
	bytesform   gcetcbendorsement.BytesForm
	endorsement *epb.VMLaunchEndorsement
}

type sevValidateCommand struct {
	endorsementPath string
	root            string
	// derived
	content     []byte
	endorsement *epb.VMLaunchEndorsement
}

func sevFrom(ctx context.Context) (*sevCommand, error) {
	if c, ok := ctx.Value(sevKey).(*sevCommand); ok {
		return c, nil
	}
	return nil, errNoSevPolicy
}

func (c *sevPolicyCommand) persistentPreRunE(cmd *cobra.Command, args []string) error {
	backend, err := backendFrom(cmd.Context())
	if err != nil {
		return err
	}
	// Check positional argument
	if len(args) != 1 {
		return fmt.Errorf("sev-policy expects exactly one positional argument, got %d", len(args))
	}
	if c.outform == "textproto" {
		c.textproto = true
	} else if c.bytesform, err = gcetcbendorsement.ParseBytesForm(c.outform); err != nil {
		return err
	}
	endorsement := args[0]
	content, err := backend.IO.ReadFile(endorsement)
	if err != nil {
		return fmt.Errorf("failed to read endorsement file %q: %v", endorsement, err)
	}
	c.endorsement = &epb.VMLaunchEndorsement{}
	if err := proto.Unmarshal(content, c.endorsement); err != nil {
		return fmt.Errorf("failed to unmarshal endorsement file %q: %v", endorsement, err)
	}

	return nil
}

func (c *sevPolicyCommand) runE(cmd *cobra.Command, args []string) error {
	backend, err := backendFrom(cmd.Context())
	if err != nil {
		return err
	}
	s, err := sevFrom(cmd.Context())
	if err != nil {
		return err
	}
	policy, err := gcetcbendorsement.SevPolicy(cmd.Context(), c.endorsement, &gcetcbendorsement.SevPolicyOptions{
		Base:                  s.basePolicy,
		Overwrite:             s.overwrite,
		LaunchVmsas:           s.launchVmsas,
		AllowUnspecifiedVmsas: s.allowUnspecifiedVmsas,
	})
	if err != nil {
		return fmt.Errorf("failed to generate sev policy: %v", err)
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
		return fmt.Errorf("failed to marshal sev policy: %v", err)
	}
	return gcetcbendorsement.WriteBytesForm(bin, c.bytesform, out)
}

func makeSevPolicyCommand(ctx context.Context) *cobra.Command {
	c := &sevPolicyCommand{}
	cmd := &cobra.Command{
		Use: "policy PATH [options]",
		Long: `Outputs the extended go-sev-guest check.Policy with endorsement reference values.

The mandatory PATH must be to a binary serialized VMLaunchEndorsement.
`,
		PersistentPreRunE: c.persistentPreRunE,
		RunE:              c.runE,
	}
	cmd.Flags().StringVar(&c.out, "out", "-", "Path to output serialized check.Policy. "+
		"Default - for stdout.")
	cmd.Flags().StringVar(&c.outform, "outform", "auto", "One of textproto|bin|hex|base64|auto. "+
		"Outputs the policy as either textproto or serialized binary proto in raw binary, or encoded "+
		"as hex or base64. Auto means the default is textproto if writing to a terminal, otherwise "+
		"bin.")
	cmd.SetContext(ctx)
	return cmd
}

func (c *sevValidateCommand) persistentPreRunE(cmd *cobra.Command, args []string) error {
	backend, err := backendFrom(cmd.Context())
	if err != nil {
		return err
	}
	if len(args) != 1 {
		return fmt.Errorf("sev validate expects exactly one positional argument, got %d", len(args))
	}
	attestation := args[0]
	content, err := backend.IO.ReadFile(attestation)
	if err != nil {
		return fmt.Errorf("failed to read attestation file %q: %v", attestation, err)
	}
	c.content = content
	if c.endorsementPath != "" {
		var endorsementBytes []byte
		endorsementBytes, err = backend.IO.ReadFile(c.endorsementPath)
		if err != nil {
			return fmt.Errorf("failed to read endorsement file %q: %v", c.endorsementPath, err)
		}
		c.endorsement = &epb.VMLaunchEndorsement{}
		if err := proto.Unmarshal(endorsementBytes, c.endorsement); err != nil {
			return fmt.Errorf("failed to unmarshal endorsement file %q: %v", c.endorsementPath, err)
		}
	}
	return nil
}

func (c *sevValidateCommand) runE(cmd *cobra.Command, args []string) error {
	backend, err := backendFrom(cmd.Context())
	if err != nil {
		return err
	}
	s, err := sevFrom(cmd.Context())
	if err != nil {
		return err
	}
	rot, err := rootOfTrust(cmd.Context(), c.root)
	if err != nil {
		return err
	}
	tpmat, err := extract.Attestation(c.content)
	if err != nil {
		return err
	}
	switch at := tpmat.TeeAttestation.(type) {
	case *tpmpb.Attestation_SevSnpAttestation:
		return gcetcbendorsement.SevValidate(cmd.Context(), at.SevSnpAttestation,
			&gcetcbendorsement.SevValidateOptions{
				Now:          backend.Now,
				Getter:       backend.Getter,
				Endorsement:  c.endorsement,
				Overwrite:    s.overwrite,
				BasePolicy:   s.basePolicy,
				RootsOfTrust: rot,
			})
	}

	return fmt.Errorf("unsupported attestation type %T", tpmat.TeeAttestation)
}

func makeSevValidateCommand(ctx context.Context) *cobra.Command {
	c := &sevValidateCommand{}
	cmd := &cobra.Command{
		Use: "validate PATH [-endorsement=PATH] ",
		Long: `Validates a SEV-SNP attestation report against its firmware endorsement.

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

func (c *sevCommand) persistentPreRunE(cmd *cobra.Command, _ []string) error {
	backend, err := backendFrom(cmd.Context())
	if err != nil {
		return err
	}
	// Check -base flag
	if c.base != "" {
		baseContent, err := backend.IO.ReadFile(c.base)
		if err != nil {
			return fmt.Errorf("failed to read base policy file %q: %v", c.base, err)
		}
		c.basePolicy = &cpb.Policy{}
		if err := proto.Unmarshal(baseContent, c.basePolicy); err != nil {
			return fmt.Errorf("failed to unmarshal base policy file %q: %v", c.base, err)
		}
	}
	return nil
}

func makeSevCommand(ctx0 context.Context) *cobra.Command {
	c := &sevCommand{}
	cmd := &cobra.Command{
		Use: "sev CMD [-base=PATH] [-overwrite] [-launch_vmsas=#] [-allow_unspecified_vmsas]",
		Long: `Outputs the extended go-sev-guest check.Policy with endorsement reference values.

The mandatory PATH must be to a binary serialized VMLaunchEndorsement.
`,
		PersistentPreRunE: c.persistentPreRunE,
		RunE: func(*cobra.Command, []string) error {
			return errNoSevCommand
		},
	}
	cmd.PersistentFlags().BoolVar(&c.overwrite, "overwrite", false,
		"If false, it is an error for populated base policy fields to be overwritten.")
	cmd.PersistentFlags().StringVar(&c.base, "base", "", "Path to base go-sev-guest check.Policy.")
	cmd.PersistentFlags().Uint32Var(&c.launchVmsas, "launch_vmsas", 0, "Number of VMSAs at launch.")
	cmd.PersistentFlags().BoolVar(&c.allowUnspecifiedVmsas, "allow_unspecified_vmsas", false,
		"If true, disregards the Measurement component of the endorsement when updating a policy.")
	ctx := context.WithValue(ctx0, sevKey, c)
	cmd.AddCommand(makeSevValidateCommand(ctx))
	cmd.AddCommand(makeSevPolicyCommand(ctx))
	cmd.SetContext(ctx)
	return cmd
}
