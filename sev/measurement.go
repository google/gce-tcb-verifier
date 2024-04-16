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

// Package sev implements launch measurement reconstruction given a few inputs such as firmware.
package sev

import (
	"crypto/sha512"
	"fmt"
	"math/big"

	oabi "github.com/google/gce-tcb-verifier/ovmf/abi"
	sgpb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/pkg/errors"
)

var bitWidth = map[sgpb.SevProduct_SevProductName]int{
	sgpb.SevProduct_SEV_PRODUCT_MILAN: 48,
	sgpb.SevProduct_SEV_PRODUCT_GENOA: 52,
}

// ProductHighAddress returns the highest GPA allowed for a PAGE_INFO on a given product.
// According to the SEV-SNP API documentation SNP_LAUNCH_UPDATE Actions section,
//
// "the guest physical address space is limited according to CPUID Fn80000008_EAX and
// thus the GPAs used by the firmware in measurement calculation are equally limited. Hypervisors
// should not attempt to map pages outside of this limit."
//
// Upon further clarification with AMD architects, we also should expect the address to be truncated
// to be page-aligned.
func ProductHighAddress(product sgpb.SevProduct_SevProductName) uint64 {
	return ((uint64(1) << bitWidth[product]) - 1) & ^uint64(0xfff)
}

func infoWithoutContents(digestCur []byte, gpa uint64, pageType PageType) PageInfo {
	var info PageInfo
	copy(info.digestCur[:], digestCur)
	info.length = SizeofPageInfo
	info.pageType = uint8(pageType)
	info.gpa = gpa
	return info
}

func putPageInfoDigest(info *PageInfo, out []byte) error {
	b, err := info.Bytes()
	if err != nil {
		return err
	}
	digestNew := sha512.Sum384(b)
	copy(out, digestNew[:])
	return nil
}

// SnpMeasurement represents the expected MEASUREMENT field of an SEV-SNP ATTESTATION_REPORT.
type SnpMeasurement struct {
	Digest  [48]byte
	Product sgpb.SevProduct_SevProductName
}

// Update4K extends an SnpMeasurement with a 4K page of data with a page type that measures the
// page contents.
func (m *SnpMeasurement) Update4K(gpa uint64, data []byte, pageType PageType) error {
	info := infoWithoutContents(m.Digest[:], gpa, pageType)
	contents := sha512.Sum384(data)
	copy(info.contents[:], contents[:])
	return putPageInfoDigest(&info, m.Digest[:])
}

// ZeroContentUpdate4K extends an SnpMeasurement with a 4K page of data with a page type that
// requires that the Contents component of its PAGE_INFO is all zeroes.
func (m *SnpMeasurement) ZeroContentUpdate4K(gpa uint64, pageType PageType) error {
	info := infoWithoutContents(m.Digest[:], gpa, pageType)
	return putPageInfoDigest(&info, m.Digest[:])
}

// Update extends an SnpMeasurement with several pages of data with a page type that measures the
// page contents.
func (m *SnpMeasurement) Update(gpa uint64, data []byte, pageType PageType) error {
	if err := m.checkUpdateDataGuestMemoryAlignment(gpa, uint32(len(data)), oabi.PageSize); err != nil {
		return err
	}
	for page4k := uint64(0); page4k < uint64(len(data)); page4k += oabi.PageSize {
		if err := m.Update4K(gpa+page4k, data[page4k:page4k+oabi.PageSize], pageType); err != nil {
			return err
		}
	}
	return nil
}

// ZeroContentUpdate extends an SnpMeasurement with several pages of data with a page type that
// requires the Contents component of its PAGE_INFO is all zeroes.
func (m *SnpMeasurement) ZeroContentUpdate(gpa uint64, size uint32, pageType PageType) error {
	switch pageType {
	case PageTypeVmsa:
		return errors.New("update for VMSA page type needs data contents")
	case PageTypeNormal:
		return errors.New("update for Normal page type needs data contents")
	case PageTypeUnmeasured:
	case PageTypeSecret:
	case PageTypeCpuid:
	case PageTypeZero:
	default:
		return fmt.Errorf("unknown pageType: %v", pageType)
	}
	if err := m.checkUpdateDataGuestMemoryAlignment(gpa, size, oabi.PageSize); err != nil {
		return err
	}
	for page4k := gpa; page4k < gpa+uint64(size); page4k += oabi.PageSize {
		m.ZeroContentUpdate4K(page4k, pageType)
	}
	return nil
}

// checkUpdateDataGuestMemoryAlignment returns an error if the given address span isn't aligned on
// the given alignment.
func (m *SnpMeasurement) checkUpdateDataGuestMemoryAlignment(guestUaddr uint64,
	guestLen uint32,
	alignment uint16) error {
	// Guest data must be aligned on |alignment| bytes.
	if guestUaddr%uint64(alignment) != 0 {
		return fmt.Errorf("guest data must be of aligned on 0x%x bytes. Got address 0x%x", alignment, guestUaddr)
	}
	// Guest data size must be a multiple of the alignment.
	if guestLen%uint32(alignment) != 0 {
		return fmt.Errorf("guest data must be of multiple of: 0x%x. Given data is size: 0x%x", alignment, guestLen)
	}
	// The high address is 1 page less than the highest byte, so we add 0x1000 on the right.
	if guestUaddr > ProductHighAddress(m.Product)+0x1000-uint64(guestLen) {
		// We can't go from uint64 to int64 safely without splitting the number into halves and readding
		// the parity bit.
		bigUaddrEven := new(big.Int).Mul(big.NewInt(int64(guestUaddr>>1)), big.NewInt(2))
		bigUaddr := new(big.Int).Add(bigUaddrEven, big.NewInt(int64(guestUaddr&1)))
		end := new(big.Int).Add(bigUaddr, big.NewInt(int64(guestLen)))
		return fmt.Errorf("address range is larger than the product can represent: [0x%x, 0x%x)", guestUaddr, end)
	}
	return nil
}
