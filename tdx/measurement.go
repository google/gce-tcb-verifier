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

// Package tdx implements launch measurement reconstruction given a few inputs such as firmware.
package tdx

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/google/gce-tcb-verifier/ovmf"
	"github.com/google/gce-tcb-verifier/ovmf/abi"
)

const (
	extensionBufferSize = 128
	mrExtendChunkSize   = 256
)

// From the TDX module specification:
//
// 14.1.1. MRTD: Build-Time Measurement Register
// The Intel TDX module measures the TD during the build process.
// The measurement register TDCS.MRTD is a SHA384 digest of the build process, designed as follows:
// • TDH.MNG.INIT begins the process by initializing the digest.
// • TDH.MEM.PAGE.ADD adds a TD private page to the TD and inserts its properties (GPA) into the
//   MRTD digest calculation.
// • Control structure pages (TDR, TDCX, TDVPR and TDVPX) and Secure EPT pages are not measured.
// • For pages whose data contribute to the TD, that data should be included in the TD measurement
//   via TDH.MR.EXTEND. TDH.MR.EXTEND inserts the data contained in those pages and its GPA, in
//   256-byte chunks, into the digest calculation. If a page will be wiped and initialized by TD
//   code, the loader may opt not to measure the initial contents of the page with TDH.MR.EXTEND.
// • The measurement is then completed by TDH.MR.FINALIZE. Once completed, further TDH.MEM.PAGE.ADDs
//   or TDEXTENDs will fail.
// MRTD extension by GPA uses a 128B buffer which includes the GPA and the leaf function name for
// uniqueness.

// Measurement represents the expected MRTD field of a TDX Quote.
type Measurement struct {
	digest hash.Hash
	// MeasureAllRegions forces all regions to be measured, even if they are not marked as
	// extendable in the metadata. This is only to be compatible with earlier versions
	// Google's hypervisor.
	MeasureAllRegions bool
}

// NewMeasurement returns a new Measurement construct for calculating the TDX MRTD.
func NewMeasurement() *Measurement {
	return &Measurement{digest: sha512.New384()}
}

// NewMeasurementTDHOBBug returns a new Measurement construct for calculating the TDX MRTD.
// This is only to be compatible with earlier versions of Google's hypervisor.
func NewMeasurementTDHOBBug() *Measurement {
	return &Measurement{digest: sha512.New384(), MeasureAllRegions: true}
}

func (m *Measurement) extend(data []byte) {
	m.digest.Write(data)
}

// TDH.MEM.PAGE.ADD [...]
//  10. Extend TDCS.MRTD with the target page GPA. Extension is done using SHA384 with a 128B
//     extension buffer composed as follows:
//     o Bytes 0 through 11 contain the ASCII string “MEM.PAGE.ADD”.
//     o Bytes 16 through 23 contain the GPA (in little-endian format).
//     o All the other bytes contain 0.
func (m *Measurement) pageAdd(gpa uint64) {
	var buf [extensionBufferSize]byte
	copy(buf[0:12], []byte("MEM.PAGE.ADD"))
	binary.LittleEndian.PutUint64(buf[16:24], gpa)
	m.extend(buf[:])
}

// TDH.MR.EXTEND
// Extend TDCS.MRTD with the chunk’s GPA and contents. Extension is done using SHA384, with three
// 128B extension buffers. The first extension buffer is composed as follows:
// o Bytes 0 through 8 contain the ASCII string “MR.EXTEND”.
// o Bytes 16 through 23 contain the GPA (in little-endian format).
// o All the other bytes contain 0.
// The other two extension buffers contain the chunk’s contents.
func (m *Measurement) mrExtend(gpa uint64, data []byte) {
	var buf [extensionBufferSize]byte
	copy(buf[0:9], []byte("MR.EXTEND"))
	binary.LittleEndian.PutUint64(buf[16:24], gpa)
	m.extend(buf[:])
	m.extend(data[0:extensionBufferSize])
	m.extend(data[extensionBufferSize:])
}

// InitMemoryRegion extends a Measurement with the initial contents of a page.
func (m *Measurement) InitMemoryRegion(region *ovmf.MaterialGuestPhysicalRegion) error {
	gpr := region.GPR
	data := region.HostBuffer
	measureBytes := region.TDVFAttributes&abi.TDXMetadataAttributeExtendMR != 0
	if m.MeasureAllRegions {
		measureBytes = true
	}
	if measureBytes && gpr.Length != uint64(len(data)) {
		return fmt.Errorf("gpr.Length %d does not match source data size %d", gpr.Length, len(data))
	}
	if gpr.Start%abi.PageSize != 0 {
		return fmt.Errorf("gpr.Start 0x%x is not page-aligned", gpr.Length)
	}
	if gpr.Length%abi.PageSize != 0 {
		return fmt.Errorf("gpr.Length 0x%x is not page-aligned", gpr.Length)
	}
	if len(data)%mrExtendChunkSize != 0 {
		return fmt.Errorf("data %d is not divisible by MR.EXTEND chunk size %d", len(data), mrExtendChunkSize)
	}
	gpa := uint64(gpr.Start)
	// Every 4K page is added and then measured in the kvm ioctl KVM_INIT_MEM_REGION.
	// There are no large pages for measurement.
	for i := 0; i < len(data); i += mrExtendChunkSize {
		if i%abi.PageSize == 0 {
			m.pageAdd(gpa + uint64(i))
		}
		if measureBytes {
			m.mrExtend(gpa+uint64(i), data[i:i+mrExtendChunkSize])
		}
	}
	return nil
}

// Finalize returns the final measurement of the VM.
func (m *Measurement) Finalize() [48]byte {
	var buf [48]byte
	copy(buf[:], m.digest.Sum(nil))
	return buf
}
