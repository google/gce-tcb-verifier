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

package tdx

import (
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
)

// EndorsementRequest encapsulates all Intel TDX-specific information needed to endorse a UEFI binary
// for TDX.
type EndorsementRequest struct {
	// Svn is the image's security version number.
	Svn uint32
	// IncludeEarlyAccept if true adds a second set of measurements where all memory is accepted
	// and therefore has different measured resource attributes.
	//
	// To be deprecated with bug fix rollout.
	IncludeEarlyAccept bool
	// The list of machine shapes whose configuration is relevant to measurement. Only relevant if
	// measureAllRegions is true to account for the Google hypervisor bug.
	//
	// To be deprecated with bug fix rollout.
	MachineShapes []string
}

func generateAllPossibleMRTDs(uefi []byte, tdxRequest *EndorsementRequest) ([]*epb.VMTdx_Measurement, error) {
	var result []*epb.VMTdx_Measurement
	// Deprecated: To be removed.
	for _, shape := range tdxRequest.MachineShapes {
		options := LaunchOptionsDefaultTDHOBBug(shape)
		meas, err := MRTD(options, uefi)
		if err != nil {
			return nil, err
		}
		result = append(result, &epb.VMTdx_Measurement{
			RamGib: uint32(shapeDesc[shape].size),
			Mrtd:   meas[:],
		})
		if tdxRequest.IncludeEarlyAccept {
			options.DisableUnacceptedMemory = true
			meas, _ = MRTD(options, uefi)
			result = append(result, &epb.VMTdx_Measurement{
				RamGib:      uint32(shapeDesc[shape].size),
				EarlyAccept: true,
				Mrtd:        meas[:],
			})
		}
	}
	meas, err := MRTD(LaunchOptionsDefault(""), uefi)
	if err != nil {
		return nil, err
	}
	result = append(result, &epb.VMTdx_Measurement{Mrtd: meas[:]})
	return result, nil
}

// UnsignedTDX returns the TDX component of a GoldenMeasurement for a given UEFI.
func UnsignedTDX(uefi []byte, tdxRequest *EndorsementRequest) (*epb.VMTdx, error) {
	// Create the basis for all endorsements.
	measurements, err := generateAllPossibleMRTDs(uefi, tdxRequest)
	if err != nil {
		return nil, err
	}
	return &epb.VMTdx{
		Svn:          tdxRequest.Svn,
		Measurements: measurements,
	}, nil
}
