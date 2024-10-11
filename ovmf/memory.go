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

package ovmf

import "github.com/google/gce-tcb-verifier/ovmf/abi"

func gprCmp(a, b GuestPhysicalRegion) int {
	if a.Start < b.Start {
		return -1
	}
	if a.Start == b.Start {
		return 0
	}
	return 1
}

func gprRange(from, to abi.EFIPhysicalAddress) GuestPhysicalRegion {
	return GuestPhysicalRegion{
		Start:  from,
		Length: uint64(to) - uint64(from),
	}
}

func (gpr GuestPhysicalRegion) end() abi.EFIPhysicalAddress {
	return abi.EFIPhysicalAddress(uint64(gpr.Start) + gpr.Length)
}

func minPhysicalAddress(x, y abi.EFIPhysicalAddress) abi.EFIPhysicalAddress {
	if x <= y {
		return x
	}
	return y
}

func maxPhysicalAddress(x, y abi.EFIPhysicalAddress) abi.EFIPhysicalAddress {
	if x >= y {
		return x
	}
	return y
}

func (gpr GuestPhysicalRegion) intersect(other GuestPhysicalRegion) GuestPhysicalRegion {
	if (gpr.Start >= other.end()) || (other.Start >= gpr.end()) {
		return GuestPhysicalRegion{}
	}
	start := maxPhysicalAddress(gpr.Start, other.Start)
	end := minPhysicalAddress(gpr.end(), other.end())
	Length := uint64(end - start)
	if Length == 0 { // Only allow a single representation of zero.
		return GuestPhysicalRegion{}
	}
	return GuestPhysicalRegion{
		Start:  start,
		Length: uint64(end - start),
	}
}

// GuestPhysicalRegion represents a region of a guest VM's memory.
type GuestPhysicalRegion struct {
	Start  abi.EFIPhysicalAddress
	Length uint64
}

// MaterialGuestPhysicalRegion represents the memory contents for a region of a guest VM's memory.
type MaterialGuestPhysicalRegion struct {
	GPR        GuestPhysicalRegion
	HostBuffer []byte
	// TDVFAttributes is a TDVF-only field for a bitset of directives for the VMM.
	TDVFAttributes uint32
}
