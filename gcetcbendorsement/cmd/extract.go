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
	"fmt"

	"github.com/google/gce-tcb-verifier/extract"
	exel "github.com/google/gce-tcb-verifier/extract/eventlog"
	"github.com/spf13/cobra"
)

const attestationFormatsUsage = `
- AMD SEV-SNP ATTESTATION_REPORT binary format
- AMD SEV-SNP ATTESTATION_REPORT binary format concatenated with the certificate GUID table auxblob.
- github.com/google/go-sev-guest/proto/sevsnp.Attestation binary serialization
- github.com/google/go-sev-guest/proto/sevsnp.Report binary serialization
- github.com/google/go-tpm-tools/proto/attest.Attestation binary serialization
`

type extractCommand struct {
	output       string
	content      []byte
	manufacturer string
	eventlogpath string
	efivarloc    string
	forceFetch   bool
}
type extractKeyType struct{}

var extractKey extractKeyType

func (c *extractCommand) persistentPreRunE(cmd *cobra.Command, args []string) error {
	backend, err := backendFrom(cmd.Context())
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return nil
	}
	if len(args) > 1 {
		return fmt.Errorf("extract expects at most one argument, got %d", len(args))
	}
	attestation := args[0]
	content, err := backend.IO.ReadFile(attestation)
	if err != nil {
		return fmt.Errorf("failed to read attestation file %q: %v", attestation, err)
	}
	c.content = content
	return nil
}

func (c *extractCommand) runE(cmd *cobra.Command, args []string) error {
	backend, err := backendFrom(cmd.Context())
	if err != nil {
		return err
	}
	var reader exel.VariableReader
	if backend.MakeEfiVariableReader != nil {
		reader = backend.MakeEfiVariableReader(c.efivarloc)
	}
	out, cleanup, err := backend.IO.Create(c.output)
	if err != nil {
		return err
	}
	defer cleanup()
	endorsement, err := extract.Endorsement(&extract.Options{
		Provider:             backend.Provider,
		Getter:               backend.Getter,
		FirmwareManufacturer: c.manufacturer,
		EventLogLocation:     c.eventlogpath,
		UEFIVariableReader:   reader,
		Quote:                c.content,
		ForceFetch:           c.forceFetch,
	})
	if err != nil {
		return err
	}
	if _, err := out.Write(endorsement); err != nil {
		return fmt.Errorf("failed to write output file %q: %v", c.output, err)
	}
	return nil
}

func makeExtract(ctx0 context.Context) *cobra.Command {
	e := &extractCommand{}
	cmd := &cobra.Command{
		Use: "extract [options] [PATH]",
		Long: `Outputs the GCE endorsement for the measurement in an attestation report.

If PATH is not provided, extract expects to be run in a TEE to extract from the context.
If PATH is provided it must be to an attestation in one of the following formats:` +
			attestationFormatsUsage,
		PersistentPreRunE: e.persistentPreRunE,
		RunE:              e.runE,
	}
	ctx := context.WithValue(ctx0, extractKey, e)
	cmd.Flags().StringVar(&e.output, "out", "endorsement.binarypb",
		"The output destination for the extracted endorsement. Default endorsement.binarypb")
	cmd.Flags().StringVar(&e.eventlogpath, "eventlog", "/sys/kernel/security/tpm0/binary_bios_measurements", "The path to the bios boot event log")
	cmd.Flags().StringVar(&e.manufacturer, "firmware_manufacturer", extract.GCEFirmwareManufacturer, "The firmware manufacturer string to search for in SP800155 events.")
	cmd.Flags().StringVar(&e.efivarloc, "efivarfs", "/sys/firmware/efi/efivars", "The efivarfs mount location.")
	cmd.Flags().BoolVar(&e.forceFetch, "force_fetch", false, "Force fetch the endorsement from the network.")
	cmd.SetContext(ctx)
	return cmd
}
