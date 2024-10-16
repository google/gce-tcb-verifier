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
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/google/gce-tcb-verifier/endorse"
	"github.com/google/gce-tcb-verifier/sev"
	"github.com/google/gce-tcb-verifier/storage/ops"
	"github.com/google/gce-tcb-verifier/storage/storagei"
	"github.com/google/gce-tcb-verifier/tdx"
	sgabi "github.com/google/go-sev-guest/abi"

	edk2pb "github.com/google/gce-tcb-verifier/proto/scrtmversion"
	sgpb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
)

const noBucket = ""

// endorseCommand stores the common flag values for the endorse subcommand that isn't directly
// represented in endorse.Context.
type endorseCommand struct {
	// Filesystem abstraction for reading files passed in as flags.
	Storage storagei.Client

	AddSnp                 bool
	AddTdx                 bool
	UefiPath               string
	SvsmPath               string
	SvsmSnpMeasurementPath string
}

// AddFlags adds any implementation-specific flags for this command component.
func (f *endorseCommand) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(&f.AddSnp, "add_snp", false,
		"Add AMD SEV-SNP information to endorsement")
	cmd.PersistentFlags().BoolVar(&f.AddTdx, "add_tdx", false,
		"Add Intel TDX information to endorsement")
	addUefiFlag(cmd, &f.UefiPath)
	cmd.PersistentFlags().StringVar(&f.SvsmPath, "svsm_path", "", "Path to SVSM binary")
	cmd.PersistentFlags().StringVar(&f.SvsmSnpMeasurementPath, "svsm_snp_measurement_path", "", "Path to SVSM measurement file for SEV-SNP")

	ec := &endorse.Context{
		SevSnp: &sev.SnpEndorsementRequest{},
		Tdx:    &tdx.EndorsementRequest{},
	}
	cmd.PersistentFlags().StringVar(&ec.CandidateName, "candidate_name", "",
		"Release candidate the signature should be submitted to directly. Optional.")
	cmd.PersistentFlags().StringVar(&ec.ReleaseBranch, "release_branch", "",
		"Release branch the signature should be submitted to directly. Optional.")
	cmd.PersistentFlags().Uint64Var(&ec.ClSpec, "clspec", 0,
		"The internal changelist number that the UEFI was built from. 0 means an external build.")
	cmd.PersistentFlags().BytesHexVar(&ec.Commit, "commit", []byte{},
		"The hexstring of the git commit that is associated with the published UEFI source. "+
			"Empty means an internal build.")
	cmd.PersistentFlags().IntVar(&ec.CommitRetries, "commit_retries", 5,
		"The number of times to attempt committing signatures after transient errors before failing.")
	addOutDirFlag(cmd, &ec.OutDir)
	addDryRunFlag(cmd, &ec.DryRun)
	addTimeFlag(cmd, &ec.Timestamp)
	cmd.PersistentFlags().StringVar(&ec.SevSnp.FamilyID, "snp_family_id", "", "SEV-SNP UUID of FAMILY_ID")
	cmd.PersistentFlags().StringVar(&ec.SevSnp.ImageID, "snp_image_id", "",
		"SEV-SNP UUID of IMAGE_ID (if empty, then random)")
	cmd.PersistentFlags().Uint32Var(&ec.SevSnp.LaunchVmsas, "snp_launch_vmsas", 0,
		"SEV-SNP number of VMSAs endorsed (0 is all sold on GCE)")
	cmd.PersistentFlags().AddGoFlag(
		amdProductVar(&ec.SevSnp.Product, "snp_product", sgpb.SevProduct_SEV_PRODUCT_MILAN,
			"SEV-SNP product line. One of Milan, Genoa"))
	cmd.PersistentFlags().BoolVar(&ec.Tdx.IncludeEarlyAccept, "tdx_include_early_accept", false, "DEPRECATED (VMM before Oct 2024): If true, adds MRTD values for all supported machine shapes with all memory configured for acceptance in the firmware.")
	cmd.PersistentFlags().StringSliceVar(&ec.Tdx.MachineShapes, "tdx_machine_shapes", nil, "DEPRECATED (VMM before Oct 2024): GCE machine shapes whose measurement-relevant configuration should be enumerated for endorsement.")
	cmd.PersistentFlags().BoolVar(&ec.MeasurementOnly, "measurement_only", false, "Only output the OVMF measurement for added technologies.")
	cmd.PersistentFlags().StringVar(&ec.SnapshotDir, "snapshot_dir", "", "Write each firmware and its signature to related files in --out_dir.")
	cmd.PersistentFlags().BoolVar(&ec.SnapshotToHead, "snapshot_to_head", false,
		"Write snapshots to HEAD, not the release branch.")
	cmd.SetContext(endorse.NewContext(cmd.Context(), ec))
}

func validateSnpFlags(f *sev.SnpEndorsementRequest) error {
	if f.FamilyID != "" {
		_, err := uuid.Parse(f.FamilyID)
		if err != nil {
			return fmt.Errorf("could not parse --family_id: %v", err)
		}
	}

	if f.ImageID != "" {
		_, err := uuid.Parse(f.ImageID)
		if err != nil {
			return fmt.Errorf("could not parse --image_id: %v", err)
		}
	}
	return nil
}

// Returns the SVN associated with the firmware at the given path.
// The SVN for SEV, TDX, and non-CoCo are all the same for now.
func scrtmMain(path string) (bool, uint32, error) {
	// Read the bundled SVN if it exists.
	versionPath := strings.Replace(path, ".fd", "_scrtm_ver.pb", 1)
	if versionBytes, err := os.ReadFile(versionPath); err == nil {
		var version edk2pb.SCRTMVersion
		if err := proto.Unmarshal(versionBytes, &version); err != nil {
			return false, 0, err
		}
		return true, uint32(version.Version), nil
	}
	return false, 0, nil
}

// PersistentPreRunE returns an error if the results of the parsed flags constitute an error.
func (f *endorseCommand) PersistentPreRunE(cmd *cobra.Command, _ []string) error {
	if f.UefiPath == "" {
		return errors.New("expected --uefi path")
	}
	if !strings.HasSuffix(f.UefiPath, ".fd") {
		return fmt.Errorf("--uefi=%q path must end with .fd", f.UefiPath)
	}
	ec, err := endorse.FromContext(cmd.Context())
	if err != nil {
		return err
	}
	ec.ImageName = path.Base(f.UefiPath)
	ok, version, err := scrtmMain(f.UefiPath)
	if err != nil {
		return err
	}
	if f.AddSnp {
		if err := validateSnpFlags(ec.SevSnp); err != nil {
			return err
		}
		if ok {
			ec.SevSnp.Svn = version
		}
	} else {
		ec.SevSnp = nil
	}
	if f.AddTdx {
		if ok {
			ec.Tdx.Svn = version
		}
	} else {
		ec.Tdx = nil
	}
	// Note: Size() does not require crypto/sha1 to be linked in.
	if len(ec.Commit) != 0 && len(ec.Commit) != crypto.SHA1.Size() {
		return fmt.Errorf("--commit must be empty or a SHA1 digest hex string. Got %d bytes, want %d",
			len(ec.Commit), crypto.SHA1.Size())
	}

	if !f.AddSnp { // drop flag values if --noadd_snp
		ec.SevSnp = nil
	}

	if ec.Timestamp.IsZero() {
		ec.Timestamp = time.Now()
	}
	return nil
}

// InitContext extends the given context with whatever else the component needs before execution.
func (f *endorseCommand) InitContext(ctx context.Context) (context.Context, error) {
	ec, err := endorse.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	// Though this file path is from a flag, the read interpretation of the flag is done in
	// initialization.
	ec.Image, err = os.ReadFile(f.UefiPath)
	if err != nil {
		return nil, fmt.Errorf("could not read UEFI file %s: %v", f.UefiPath, err)
	}
	if f.SvsmPath != "" {
		ec.SvsmImage, err = ops.ReadFile(ctx, f.Storage, noBucket, f.SvsmPath)
		if err != nil {
			return nil, fmt.Errorf("could not read SVSM file %s: %v", f.SvsmPath, err)
		}
	}
	if f.SvsmSnpMeasurementPath != "" {
		snpMeasurementTxt, err := ops.ReadFile(ctx, f.Storage, noBucket, f.SvsmSnpMeasurementPath)
		if err != nil {
			return nil, fmt.Errorf("could not read SVSM SNP measurement file: %v", err)
		}

		ec.SvsmSnpMeasurement, err = hex.DecodeString(strings.TrimSpace(string(snpMeasurementTxt)))
		if err != nil {
			return nil, fmt.Errorf("could not parse SVSM SNP measurement file %q: %v", f.SvsmSnpMeasurementPath, err)
		}
		if len(ec.SvsmSnpMeasurement) != sgabi.MeasurementSize {
			return nil, fmt.Errorf("SVSM IGVM measurement for SEV-SNP is %d bytes. Expected %d", len(ec.SvsmSnpMeasurement), sgabi.MeasurementSize)
		}
	}

	return ctx, nil
}

func makeEndorseCmd(ctx context.Context, app *AppComponents) *cobra.Command {
	cmp := Compose(app.Global, &endorseCommand{Storage: app.Storage}, app.Endorse)
	cmd := &cobra.Command{
		Use:               "endorse",
		PersistentPreRunE: cmp.PersistentPreRunE,
		RunE:              ComposeRun(cmp, endorse.VirtualFirmware),
	}
	cmd.SetContext(ctx)
	cmp.AddFlags(cmd)
	return cmd
}

// EndorseSetE returns the setter's result given the context's endorse.Context if it exists, or
// returns the missing context error.
func EndorseSetE(ctx context.Context, setter func(ec *endorse.Context) error) error {
	ec, err := endorse.FromContext(ctx)
	if err != nil {
		return err
	}
	return setter(ec)
}

// EndorseSet calls the given setter function on the context's endorse.Context if it exists, or
// returns the missing context error.
func EndorseSet(ctx context.Context, setter func(ec *endorse.Context)) error {
	return EndorseSetE(ctx, func(ec *endorse.Context) error {
		setter(ec)
		return nil
	})
}

// EndorseSetterE returns a CommandComponent that whose InitContext returns the setter's result
// when given the context's endorse.Context. Returns the missing context error if not present.
func EndorseSetterE(setter func(ec *endorse.Context) error) CommandComponent {
	return &PartialComponent{
		FInitContext: func(ctx context.Context) (context.Context, error) {
			return ctx, EndorseSetE(ctx, setter)
		},
	}
}

// EndorseSetter returns a CommandComponent that runs the given initialization function with the
// context's endorse.Context if present.
func EndorseSetter(setter func(ec *endorse.Context)) CommandComponent {
	return &PartialComponent{
		FInitContext: func(ctx context.Context) (context.Context, error) {
			return ctx, EndorseSet(ctx, setter)
		},
	}
}
