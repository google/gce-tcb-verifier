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
	"bytes"
	"context"
	"encoding/pem"
	"fmt"

	"google.golang.org/protobuf/proto"

	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/go-sev-guest/abi"
	cpb "github.com/google/go-sev-guest/proto/check"
)

// SevPolicyOptions contains options for modifying a go-sev-guest validation policy from an
// endorsement.
type SevPolicyOptions struct {
	Base *cpb.Policy
	// LaunchVmsas is the number of expected Vmsas the VM was launched with. A policy is limited to
	// check a single measurement.
	LaunchVmsas uint32
	// Overwrite if false, it is an error for reference values from Endorsement to overwrite the
	// associated fields in the Base policy.
	Overwrite bool
	// AllowUnspecifiedVmsas indicates that LaunchVmsas == 0 should not be an error, and the
	// measurement should be disregarded.
	AllowUnspecifiedVmsas bool
}

func allowBytes(sbytes, pbytes []byte) bool {
	if len(pbytes) != 0 {
		return bytes.Equal(sbytes, pbytes)
	}
	return true
}

func policyModificationAllowed(sev *epb.VMSevSnp, policy *cpb.Policy, opts *SevPolicyOptions) error {
	if policy.GetPolicy() != 0 && policy.GetPolicy() != sev.GetPolicy() {
		return fmt.Errorf("policy %d overwritten with %d", policy.GetPolicy(), sev.GetPolicy())
	}
	if opts.LaunchVmsas != 0 {
		meas := sev.Measurements[opts.LaunchVmsas]
		if !allowBytes(meas, policy.GetMeasurement()) {
			return fmt.Errorf("measurement %v overwritten with %v", policy.GetMeasurement(), meas)
		}
	}
	return nil
}

func modifyPolicy(sev *epb.VMSevSnp, policy *cpb.Policy, opts *SevPolicyOptions) error {
	if !opts.Overwrite {
		if err := policyModificationAllowed(sev, policy, opts); err != nil {
			return err
		}
		// Minimum in a base policy is allowed to be less than or equal to the endorsed SVN if non-zero.
		if policy.GetMinimumGuestSvn() != 0 && sev.Svn < policy.GetMinimumGuestSvn() {
			return fmt.Errorf("minimum_guest_svn %d rejects %d", policy.GetMinimumGuestSvn(),
				sev.Svn)
		}
	}
	// Otherwise, the GUEST_SVN is not set by GCE due to not using an IDBLOCK.

	// Despite these values getting signed, they are not expected in GCE since GCE does not use an
	// IDBLOCK.
	// policy.ImageId = sev.GetImageId()
	// policy.FamilyId = sev.GetFamilyId()

	// Allow the base policy to overwrite the signed policy if --overwrite is given.
	if !opts.Overwrite || policy.Policy == 0 {
		policy.Policy = sev.GetPolicy()
	}

	if opts.LaunchVmsas == 0 {
		// Regardless of Overwrite, unspecified VMSAs needs to be present for --launch_vmsas=0.
		if !opts.AllowUnspecifiedVmsas {
			return fmt.Errorf("launch_vmsas must be set to modify policy for endorsed measurement")
		}
		// Otherwise skip specifying a policy measurement.
	} else {
		meas, ok := sev.Measurements[opts.LaunchVmsas]
		if !ok {
			var plural string
			if opts.LaunchVmsas != 1 {
				plural = "s"
			}
			return fmt.Errorf("failed to find measurement for %d VMSA%s", opts.LaunchVmsas, plural)
		}
		policy.Measurement = meas
	}
	// The CA bundle is not an overwrite but an extension of trusted keys.
	if len(sev.GetCaBundle()) != 0 {
		// Identity..Author
		id, idrest := pem.Decode(sev.GetCaBundle())
		if id == nil {
			return fmt.Errorf("could not parse CA bundle as PEM")
		}
		if id.Type != "CERTIFICATE" {
			return fmt.Errorf("ca bundle identity key PEM type is %q, want CERTIFICATE", id.Type)
		}
		policy.TrustedIdKeys = append(policy.TrustedIdKeys, id.Bytes)
		if len(idrest) != 0 {
			auth, authrest := pem.Decode(idrest)
			if auth == nil {
				return fmt.Errorf("could not parse CA bundle remainder as PEM")
			}
			if auth.Type != "CERTIFICATE" {
				return fmt.Errorf("ca bundle author key PEM type is %q, want CERTIFICATE", auth.Type)
			}
			policy.TrustedAuthorKeys = append(policy.TrustedAuthorKeys, auth.Bytes)
			if len(authrest) != 0 {
				return fmt.Errorf("ca bundle longer than expected. Remaining %v", authrest)
			}
		}
	}
	return nil
}

// SevPolicy extends a base go-sev-guest validation policy with reference values contained in the
// endorsement.
func SevPolicy(ctx context.Context, endorsement *epb.VMLaunchEndorsement, opts *SevPolicyOptions) (*cpb.Policy, error) {
	golden := &epb.VMGoldenMeasurement{}
	if err := proto.Unmarshal(endorsement.GetSerializedUefiGolden(), golden); err != nil {
		return nil, fmt.Errorf("failed to unmarshal serialized golden measurement: %v", err)
	}
	if golden.SevSnp == nil {
		return nil, fmt.Errorf("golden measurement does not contain sev_snp")
	}

	var result *cpb.Policy
	if opts.Base == nil {
		result = &cpb.Policy{
			Policy: abi.SnpPolicyToBytes(abi.SnpPolicy{
				ABIMinor:     0,
				ABIMajor:     0,
				SMT:          true,
				MigrateMA:    true,
				Debug:        false,
				SingleSocket: false,
			}),
			MinimumVersion: "0.0"}
	} else {
		result = proto.Clone(opts.Base).(*cpb.Policy)
	}
	if err := modifyPolicy(golden.SevSnp, result, opts); err != nil {
		return nil, err
	}
	return result, nil
}
