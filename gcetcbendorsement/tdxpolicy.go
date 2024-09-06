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
	"fmt"

	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	tcpb "github.com/google/go-tdx-guest/proto/checkconfig"
	"google.golang.org/protobuf/proto"
)

// TdxPolicyOptions contains options for modifying a go-tdx-guest validation policy from an
// endorsement.
type TdxPolicyOptions struct {
	Base *tcpb.Policy
	// RAMGiB is the amount of RAM that the VM launched with as accounted by its TDHOB.
	RAMGiB int
	// Overwrite indicates that the policy should be modified even if it already has values.
	Overwrite bool
}

func modifyTdxPolicy(tdxpolicy *tcpb.Policy, mrtds [][]byte, opts *TdxPolicyOptions) error {
	if tdxpolicy.TdQuoteBodyPolicy == nil {
		tdxpolicy.TdQuoteBodyPolicy = &tcpb.TDQuoteBodyPolicy{}
	} else if tdxpolicy.TdQuoteBodyPolicy.AnyMrTd != nil && !opts.Overwrite {
		return fmt.Errorf("tdx policy already has any_mr_td. Try again with --overwrite")
	}
	tdxpolicy.TdQuoteBodyPolicy.AnyMrTd = mrtds
	return nil
}

// TdxPolicy extends a base go-tdx-guest validation policy with reference values contained in the
// endorsement.
func TdxPolicy(ctx context.Context, endorsement *epb.VMLaunchEndorsement, opts *TdxPolicyOptions) (*tcpb.Policy, error) {
	golden := &epb.VMGoldenMeasurement{}
	if err := proto.Unmarshal(endorsement.GetSerializedUefiGolden(), golden); err != nil {
		return nil, fmt.Errorf("failed to unmarshal serialized golden measurement: %v", err)
	}
	if golden.Tdx == nil {
		return nil, fmt.Errorf("golden measurement does not contain tdx")
	}

	var result *tcpb.Policy
	if opts.Base == nil {
		result = &tcpb.Policy{}
	} else {
		result = proto.Clone(opts.Base).(*tcpb.Policy)
	}
	var mrtds [][]byte
	for _, m := range golden.Tdx.Measurements {
		// If RAMGiB is 0, we try all measurements.
		// If nonzero, skip sizes that don't match.
		if opts.RAMGiB != 0 && m.GetRamGib() != uint32(opts.RAMGiB) {
			continue
		}
		mrtds = append(mrtds, m.GetMrtd())
	}
	if err := modifyTdxPolicy(result, mrtds, opts); err != nil {
		return nil, err
	}
	return result, nil
}
