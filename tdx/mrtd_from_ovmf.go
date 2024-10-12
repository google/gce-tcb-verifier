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
	"github.com/google/gce-tcb-verifier/ovmf/abi"
)

const (
	mib           = 0x100000
	gib           = 0x40000000
	mmioHoleStart = 3 * gib
	mmioHoleEnd   = 4 * gib
)

type numaDesc struct {
	size           int // In GiB
	nodes          int
	maxSizePerNode int // In GiB
}

func regionsForShape(shape numaDesc) []ovmf.GuestPhysicalRegion {
	regions := []ovmf.GuestPhysicalRegion{
		{Start: 0, Length: mmioHoleStart},       // Lower 3GiB
		{Start: 4*gib - 2*mib, Length: 2 * mib}, // Top 2MiB under 4GiB for TDVF
	}
	Start := abi.EFIPhysicalAddress(mmioHoleEnd)
	ShapeSizeBytes := uint64(shape.size * gib)
	taken := uint64(mmioHoleStart)
	MaxNodeSize := uint64(shape.maxSizePerNode * gib)
	if ShapeSizeBytes < taken || MaxNodeSize < taken {
		panic("bad shape constants")
	}
	Size := ShapeSizeBytes - taken
	for node := 0; node < shape.nodes; node++ {
		length := MaxNodeSize - uint64(taken)
		if Size < length {
			length = Size
		}
		regions = append(regions, ovmf.GuestPhysicalRegion{Start: Start, Length: length})
		Start += abi.EFIPhysicalAddress(length)
		Size -= length
		taken = 0
	}
	return regions
}

// https://cloud.google.com/compute/docs/general-purpose-machines#c3_machine_types
var shapeDesc = map[string]numaDesc{
	"c3-standard-4":   {size: 16, nodes: 1, maxSizePerNode: 176},
	"c3-standard-8":   {size: 32, nodes: 1, maxSizePerNode: 176},
	"c3-standard-22":  {size: 88, nodes: 1, maxSizePerNode: 176},
	"c3-standard-44":  {size: 176, nodes: 1, maxSizePerNode: 176},
	"c3-standard-88":  {size: 352, nodes: 2, maxSizePerNode: 176},
	"c3-standard-176": {size: 704, nodes: 4, maxSizePerNode: 176},
}

func machineTypeToRAMBanks(machineType string) ([]ovmf.GuestPhysicalRegion, error) {
	desc, ok := shapeDesc[machineType]
	if !ok {
		return nil, fmt.Errorf("unsupported machine type: %s", machineType)
	}
	return regionsForShape(desc), nil
}

// LaunchOptions contains GCE API surface options for launching a TDX VM that translate into the
// relevant memory bank topology for measurement.
type LaunchOptions struct {
	// GuestRAMBanks describes the RAM banks that inform TDHOB's construction.
	//
	// Deprecated: to be removed.
	GuestRAMBanks []ovmf.GuestPhysicalRegion
	// DisableUnacceptedMemory adds the early accept attribute to all memory in the TDHOB.
	//
	// Deprecated: to be removed.
	DisableUnacceptedMemory bool
	// MeasureAllRegions forces all regions to be measured, even if they are not marked as
	// extendable in the metadata. This is only to be compatible with earlier versions
	// Google's hypervisor.
	MeasureAllRegions bool
}

// LaunchOptionsDefault returns a default LaunchOptions instance.
func LaunchOptionsDefault(_ string) *LaunchOptions {
	return &LaunchOptions{}
}

// LaunchOptionsDefaultTDHOBBug returns a default LaunchOptions instance that accounts for the
// Google hypervisor bug that measures all TDVF metadata regions.
func LaunchOptionsDefaultTDHOBBug(machineType string) *LaunchOptions {
	banks, _ := machineTypeToRAMBanks(machineType)
	return &LaunchOptions{GuestRAMBanks: banks, MeasureAllRegions: true}
}

// MRTD returns the expected MRTD from booting a given OVMF and Google Compute Engine configuration.
func MRTD(opts *LaunchOptions, fw []byte) ([48]byte, error) {
	var regions []*ovmf.MaterialGuestPhysicalRegion
	var err error
	var m *Measurement
	if opts.MeasureAllRegions {
		m = NewMeasurementTDHOBBug()
	} else {
		m = NewMeasurement()
	}
	if opts.DisableUnacceptedMemory {
		regions, err = ovmf.ExtractMaterialGuestPhysicalRegionsNoUnacceptedMemory(
			fw, opts.GuestRAMBanks)
	} else if opts.MeasureAllRegions {
		regions, err = ovmf.ExtractMaterialGuestPhysicalRegionsTDHOBBug(fw, opts.GuestRAMBanks)
	} else {
		regions, err = ovmf.ExtractMaterialGuestPhysicalRegions(fw)
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
