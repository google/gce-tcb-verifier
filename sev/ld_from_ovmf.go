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

package sev

import (
	"fmt"

	"github.com/google/gce-tcb-verifier/ovmf"
	oabi "github.com/google/gce-tcb-verifier/ovmf/abi"
	spb "github.com/google/gce-tcb-verifier/proto/sev"
	sgpb "github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

// Expected values for VMCB Save Area. This is needed in SEV-ES to reconstruct
// the expected measurement coming from the AMD Secure Processor. The values
// here are for the 1st CPU (BSP); For APS the value of cs.base and rip must be
// overwritten with the values read from the SEV-ES Reset Block.
// The default g_pat is 0x0007040600070406 but gets overwritten to 0x00070106 by the GCE hypervisor.
const (
	KiB    = 1024
	MiB    = 1024 * KiB
	GiB    = 1024 * MiB
	RomTop = 4 * GiB

	VmsaV1 = `
  es { attrib: 0x0093 limit: 0xffff }
  cs { selector: 0xf000 attrib: 0x009b limit: 0xffff base: 0xffff0000 }
  ss { attrib: 0x0093 limit: 0xffff }
  ds { attrib: 0x0093 limit: 0xffff }
  fs { attrib: 0x0093 limit: 0xffff }
  gs { attrib: 0x0093 limit: 0xffff }
  gdtr { limit: 0xffff }
  ldtr { attrib: 0x0082 limit: 0xffff }
  idtr { limit: 0xffff }
  tr { attrib: 0x008b limit: 0xffff }
  efer: 0x00001000
  cr0: 0x00000010
  cr4: 0x00000040
  dr6: 0xffff0ff0
  dr7: 0x00000400
  rip: 0x0000fff0
  rflags: 0x00000002
  g_pat: 0x00070106
  rdx: 0x00000600
  xcr0: 0x00000001
	sev_features: 0x00000001
`
)

// LaunchOptions represents the expected measurement-impacting configurable features of a VM launch.
type LaunchOptions struct {
	// Vcpus is the number of VCPUs measured at launch. For images that use SEV-SNP's AP boot
	// protocol, this should be 1.
	Vcpus   int
	Product sgpb.SevProduct_SevProductName
}

// LaunchOptionsDefault returns a default object of LaunchOptions (Vcpus == 1).
func LaunchOptionsDefault() *LaunchOptions {
	return &LaunchOptions{Vcpus: 1, Product: sgpb.SevProduct_SEV_PRODUCT_MILAN}
}

func measureVmsa(measurement *SnpMeasurement, expectedVmsas []*spb.VmcbSaveArea, opts *LaunchOptions) error {
	for _, vmsa := range expectedVmsas {
		vmsaData := make([]byte, oabi.PageSize)
		if err := PutVmsa(vmsa, vmsaData); err != nil {
			return err
		}
		// V1 of SNP support in KVM measures all VMSAs with a GPA of -1. That gets truncated according
		// to the CPUID addressability and page alignment as calculated by ProductHighAddress.
		if err := measurement.Update(ProductHighAddress(opts.Product), vmsaData, PageTypeVmsa); err != nil {
			return err
		}
	}
	return nil
}

func measureZeroContentUefiPages(data *ovmf.SevData, measurement *SnpMeasurement) error {
	sections, err := data.SnpMetadataSections()
	if err != nil {
		return err
	}

	for _, section := range sections {
		var sectionType PageType
		switch section.Kind {
		case oabi.SevUnmeasuredSection:
			sectionType = PageTypeUnmeasured
		case oabi.SevSecretSection:
			sectionType = PageTypeSecret
		case oabi.SevCpuidSection:
			sectionType = PageTypeCpuid
		case oabi.SevSvsmCaaSection:
			sectionType = PageTypeZero
		default:
			return fmt.Errorf("unknown OVMF page section type: %v", section.Kind)
		}

		if err := measurement.ZeroContentUpdate(uint64(section.Address), section.Length,
			sectionType); err != nil {
			return err
		}
	}
	return nil
}

func measureUefi(data *ovmf.SevData, measurement *SnpMeasurement, uefi []byte) error {
	// Uefi is loaded at (4 *GiB - uefi.size())
	if err := measurement.Update(uint64(RomTop-len(uefi)), uefi, PageTypeNormal); err != nil {
		return err
	}

	// Classify UEFI sections unmeasured, secret, or CPUID. These page types do
	// not have their contents measured.
	return measureZeroContentUefiPages(data, measurement)
}

func prepareVmsas(options *LaunchOptions, data *ovmf.SevData) ([]*spb.VmcbSaveArea, error) {
	bspVmsa := &spb.VmcbSaveArea{}
	uom := prototext.UnmarshalOptions{}
	if err := uom.Unmarshal([]byte(VmsaV1), bspVmsa); err != nil {
		return nil, fmt.Errorf("VMSA text format parse error: %v", err)
	}

	expectedVmsas := []*spb.VmcbSaveArea{bspVmsa}
	if options.Vcpus == 1 {
		return expectedVmsas, nil
	}
	block, err := data.SevEsResetBlock()
	if err != nil {
		return nil, err
	}
	rip, csBase, err := ovmf.GetRipAndCsBaseFromSevEsResetBlock(block)
	if err != nil {
		return nil, err
	}
	next := proto.Clone(bspVmsa).(*spb.VmcbSaveArea)
	if next.Cs == nil {
		next.Cs = &spb.VmcbSeg{}
	}
	next.Cs.Base = csBase
	next.Rip = rip
	for i := 0; i < options.Vcpus-1; i++ {
		expectedVmsas = append(expectedVmsas, next)
	}
	return expectedVmsas, nil
}

// LaunchDigest computes the SEV-SNP expected MEASUREMENT from a given UEFI and the number of vCPUs
// at boot
func LaunchDigest(options *LaunchOptions, serializedUefi []byte) ([]byte, error) {
	measurement := &SnpMeasurement{Product: options.Product}

	if options.Vcpus < 1 {
		return nil, fmt.Errorf("vcpus at launch is %d. Want at least 1", options.Vcpus)
	}

	data := &ovmf.SevData{SevEs: true, SevSnp: true}
	if err := data.ExtractFromFirmware(serializedUefi); err != nil {
		return nil, err
	}

	if err := measureUefi(data, measurement, serializedUefi); err != nil {
		return nil, err
	}
	loadedVmsas, err := prepareVmsas(options, data)
	if err != nil {
		return nil, err
	}
	if err := measureVmsa(measurement, loadedVmsas, options); err != nil {
		return nil, err
	}
	return measurement.Digest[:], nil
}
