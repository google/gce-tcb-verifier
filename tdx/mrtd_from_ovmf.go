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
	"fmt"

	"github.com/google/gce-tcb-verifier/ovmf"
)

const (
	mib = 0x100000
	gib = 0x40000000
)

func regionsForGB(sizeInGB int) []ovmf.GuestPhysicalRegion {
	return []ovmf.GuestPhysicalRegion{
		{Start: 0, Length: 3 * gib},                        // Lower 3GiB
		{Start: 4*gib - 2*mib, Length: 2 * mib},            // Top 2MiB under 4GiB for TDVF
		{Start: 4 * gib, Length: uint64(sizeInGB-3) * gib}, // Rest of memory
	}
}

// https://cloud.google.com/compute/docs/general-purpose-machines#c3_machine_types
var shapeRAMGib = map[string]int{
	"c3-standard-4":   16,
	"c3-standard-8":   32,
	"c3-standard-22":  88,
	"c3-standard-44":  176,
	"c3-standard-88":  352,
	"c3-standard-176": 704,
}

var shapeBanks = map[string][]ovmf.GuestPhysicalRegion{
	"c3-standard-4":   regionsForGB(shapeRAMGib["c3-standard-4"]),
	"c3-standard-8":   regionsForGB(shapeRAMGib["c3-standard-8"]),
	"c3-standard-22":  regionsForGB(shapeRAMGib["c3-standard-22"]),
	"c3-standard-44":  regionsForGB(shapeRAMGib["c3-standard-44"]),
	"c3-standard-88":  regionsForGB(shapeRAMGib["c3-standard-88"]),
	"c3-standard-176": regionsForGB(shapeRAMGib["c3-standard-176"]),
}

func machineTypeToRAMBanks(machineType string) ([]ovmf.GuestPhysicalRegion, error) {
	result, ok := shapeBanks[machineType]
	if !ok {
		return nil, fmt.Errorf("unsupported machine type: %s", machineType)
	}
	return result, nil
}

// LaunchOptions contains GCE API surface options for launching a TDX VM that translate into the
// relevant memory bank topology for measurement.
type LaunchOptions struct {
	GuestRAMBanks           []ovmf.GuestPhysicalRegion
	DisableUnacceptedMemory bool
}

// LaunchOptionsDefault returns a default LaunchOptions instance.
func LaunchOptionsDefault(machineType string) *LaunchOptions {
	banks, _ := machineTypeToRAMBanks(machineType)
	return &LaunchOptions{GuestRAMBanks: banks}
}

// MRTD returns the expected MRTD from booting a given OVMF and Google Compute Engine configuration.
func MRTD(opts *LaunchOptions, fw []byte) ([48]byte, error) {
	var regions []*ovmf.MaterialGuestPhysicalRegion
	var err error
	m := NewMeasurement()
	if opts.DisableUnacceptedMemory {
		regions, err = ovmf.ExtractMaterialGuestPhysicalRegionsNoUnacceptedMemory(
			fw, opts.GuestRAMBanks)
	} else {
		regions, err = ovmf.ExtractMaterialGuestPhysicalRegions(fw, opts.GuestRAMBanks)
	}
	if err != nil {
		return [48]byte{}, err
	}
	for _, region := range regions {
		if err := m.InitMemoryRegion(region); err != nil {
			return [48]byte{}, err
		}
	}
	return m.Finalize(), nil
}
