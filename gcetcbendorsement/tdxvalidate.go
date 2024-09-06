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
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/google/gce-tcb-verifier/cmd/output"
	"github.com/google/gce-tcb-verifier/extract"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/gce-tcb-verifier/verify"
	tcpb "github.com/google/go-tdx-guest/proto/checkconfig"
	"github.com/google/go-tdx-guest/validate"
	tpmpb "github.com/google/go-tpm-tools/proto/attest"
	"google.golang.org/protobuf/proto"
)

// TdxValidateOptions holds options for the tdx-validate command.
type TdxValidateOptions struct {
	Endorsement    *epb.VMLaunchEndorsement
	BasePolicy     *tcpb.Policy
	Overwrite      bool
	RootsOfTrust   *x509.CertPool
	Now            time.Time
	Getter         verify.HTTPSGetter
	ExpectedRAMGiB int
}

// TdxValidate validates an attestation against the given or extracted endorsement and an optional
// base policy.
func TdxValidate(ctx context.Context, attestation []byte, opts *TdxValidateOptions) error {
	var validateQuote any
	var err error
	endorsement := opts.Endorsement
	tpmAttestation, err := extract.Attestation(attestation)
	if err != nil {
		return fmt.Errorf("failed to parse attestation: %v", err)
	}
	switch ta := tpmAttestation.TeeAttestation.(type) {
	case *tpmpb.Attestation_TdxAttestation:
		validateQuote = ta.TdxAttestation
	default:
		return fmt.Errorf("unsupported TDX attestation type %T", ta)
	}
	if endorsement == nil {
		output.Infof(ctx, "Extracting endorsement from attestation")
		eopts := extract.DefaultOptions()
		eopts.Quote = attestation
		endorsementbytes, err := extract.Endorsement(eopts)
		if err != nil {
			return err
		}
		endorsement = &epb.VMLaunchEndorsement{}
		if err := proto.Unmarshal(endorsementbytes, endorsement); err != nil {
			return fmt.Errorf("failed to unmarshal endorsement: %v", err)
		}
	}
	policy, err := TdxPolicy(ctx, endorsement, &TdxPolicyOptions{
		Base:      opts.BasePolicy,
		Overwrite: opts.Overwrite,
		RAMGiB:    opts.ExpectedRAMGiB,
	})
	if err != nil {
		return err
	}
	vopts, err := validate.PolicyToOptions(policy)
	if err != nil {
		return fmt.Errorf("could not translate policy to validation options: %v", err)
	}
	return validate.TdxQuote(validateQuote, vopts)
}
