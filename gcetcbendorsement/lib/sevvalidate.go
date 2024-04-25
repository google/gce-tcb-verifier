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
	"crypto/x509"
	"fmt"
	"context"
	"time"

	"github.com/google/gce-tcb-verifier/extract/extractsev"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/gce-tcb-verifier/sev"
	"github.com/google/gce-tcb-verifier/verify"
	cpb "github.com/google/go-sev-guest/proto/check"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	"google.golang.org/protobuf/proto"
)

// SevValidateOptions holds options for the sev-validate command.
type SevValidateOptions struct {
	Endorsement         *epb.VMLaunchEndorsement
	BasePolicy          *cpb.Policy
	Overwrite           bool
	RootsOfTrust        *x509.CertPool
	Now                 time.Time
	Getter              verify.HTTPSGetter
	ExpectedLaunchVmsas uint32
}

func unmarshalEndorsement(data []byte) (*epb.VMLaunchEndorsement, error) {
	endorsement := &epb.VMLaunchEndorsement{}
	err := proto.Unmarshal(data, endorsement)
	if err != nil {
		return nil, fmt.Errorf("failed unmarshalling VMLaunchEndorsement: %v", err)
	}
	return endorsement, nil
}

func extractSevFromAttestation(attestation *spb.Attestation) *epb.VMLaunchEndorsement {
	if len(attestation.GetCertificateChain().GetExtras()) == 0 {
		return nil
	}

	e, _ := unmarshalEndorsement(attestation.GetCertificateChain().GetExtras()[sev.GCEFwCertGUID])
	return e
}

func extractEndorsement(attestation *spb.Attestation, opts *SevValidateOptions) (*epb.VMLaunchEndorsement, error) {
	if endorsement := extractSevFromAttestation(attestation); endorsement != nil {
		return endorsement, nil
	}

	// Last attempt to extract the endorsement downloads from the gce_tcb_integrity bucket.
	if opts.Getter == nil {
		return nil, fmt.Errorf("could not extract endorsement")

	}
	obj := extractsev.GceTcbObjectName(sev.GCEUefiFamilyID, attestation.GetReport().GetMeasurement())
	url := verify.GceTcbURL(obj)
	bin, err := opts.Getter.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get endorsement: %v", err)
	}
	return unmarshalEndorsement(bin)
}

// SevValidate validates an attestation against the given or extracted endorsement and an optional
// base policy.
func SevValidate(ctx context.Context, attestation *spb.Attestation, opts *SevValidateOptions) error {
	var err error
	endorsement := opts.Endorsement
	if endorsement == nil {
		endorsement, err = extractEndorsement(attestation, opts)
		if err != nil {
			return err
		}
	}
	policy, err := SevPolicy(ctx, endorsement, &SevPolicyOptions{
		Base:                  opts.BasePolicy,
		Overwrite:             opts.Overwrite,
		LaunchVmsas:           opts.ExpectedLaunchVmsas,
		AllowUnspecifiedVmsas: true,
	})
	if err != nil {
		return err
	}
	vopts, err := validate.PolicyToOptions(policy)
	if err != nil {
		return fmt.Errorf("could not translate policy to validation options: %v", err)
	}
	vopts.CertTableOptions = map[string]*validate.CertEntryOption{
		sev.GCEFwCertGUID: {
			Kind: validate.CertEntryRequire,
			Validate: verify.SNPValidateFunc(&verify.Options{
				SNP:          &verify.SNPOptions{ExpectedLaunchVMSAs: opts.ExpectedLaunchVmsas},
				RootsOfTrust: opts.RootsOfTrust,
				Now:          opts.Now,
				Getter:       opts.Getter,
			})},
	}
	return validate.SnpAttestation(attestation, vopts)
}
