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
	"encoding/binary"
	"fmt"

	spb "github.com/google/gce-tcb-verifier/proto/sev"
)

// Types and values specified in AMD SNP API revision 1.51
// https://www.amd.com/system/files/TechDocs/56860.pdf

// Permissions assignable in the RMP for a page's assess permissions by a vCPU
// with VPML number specified in vmpl[n]_perms.
// VMPL0 has all access permissions.
const (
	VmplPermissionExecuteSupervisor = uint8(1 << 3)
	VmplPermissionExecuteUser       = uint8(1 << 2)
	VmplPermissionWrite             = uint8(1 << 1)
	VmplPermissionRead              = uint8(1 << 0)

	// Flag for whether a page is included in the Initial Measured Image (IMI).
	IsInitialMeasuredImage = 1

	SizeofPageInfo = 0x70

	// SizeofVmcbSeg is the ABI size of an AMD-V VMCB segment struct.
	SizeofVmcbSeg = 16
	// SizeofVmsa is the ABI size of the SEV-ES VMCB secure save area.
	SizeofVmsa = 0x670
)

// PageType is an enum to safe-guard validity of Secure Nested Paging (SNP) page types.
// SNP ABI documentation for SNP_LAUNCH_UPDATE, Encodings for the PAGE_TYPE Field.
type PageType uint8

const (
	// PageTypeNormal is the SEV-SNP ABI encoding of a normally measured page.
	PageTypeNormal PageType = iota + 1
	// PageTypeVmsa is the SEV-SNP ABI encoding of an encrypted VMCB save area.
	PageTypeVmsa
	// PageTypeZero is the SEV-SNP ABI encoding of a zero page.
	PageTypeZero
	// PageTypeUnmeasured is the SEV-SNP ABI encoding of an unmeasured page
	PageTypeUnmeasured
	// PageTypeSecret is the SEV-SNP ABI encoding of the special Secrets page that the firmware will
	// populate at launch.
	PageTypeSecret
	// PageTypeCpuid is the SEV-SNP ABI encoding of a CPUID table page that the firmware will check
	// at launch.
	PageTypeCpuid
)

// PageInfo represents an extension to the running launch_digest of an SNP launch. This
// struct is documented AMD ABI in SNP firmware API revision 1.51 as PAGE_INFO:
type PageInfo struct {
	// 48 is SHA384_DIGEST_LENGTH
	digestCur  [48]byte
	contents   [48]byte
	length     uint16
	pageType   uint8
	imi        uint8 // Bits 7:1 are reserved.
	vmpl1Perms uint8
	vmpl2Perms uint8
	vmpl3Perms uint8
	gpa        uint64
}

// Put writes the PageInfo into data as an SEV-SNP PAGE_INFO byte sequence.
func (p *PageInfo) Put(data []byte) error {
	if len(data) < SizeofPageInfo {
		return fmt.Errorf("data too small for PageInfo: %d < %d", len(data), SizeofPageInfo)
	}
	copy(data[0:0x30], p.digestCur[:])
	copy(data[0x30:0x60], p.contents[:])
	binary.LittleEndian.PutUint16(data[0x60:0x62], p.length)
	data[0x62] = p.pageType
	data[0x63] = p.imi

	vmplPerms :=
		(uint32(p.vmpl1Perms) << 8) |
			(uint32(p.vmpl2Perms) << 16) |
			(uint32(p.vmpl3Perms) << 24)
	binary.LittleEndian.PutUint32(data[0x64:0x68], vmplPerms)
	binary.LittleEndian.PutUint64(data[0x68:0x70], p.gpa)
	return nil
}

// Bytes serializes a PageInfo into an SEV-SNP PAGE_INFO byte sequence.
func (p *PageInfo) Bytes() ([]byte, error) {
	result := make([]byte, SizeofPageInfo)
	if err := p.Put(result); err != nil {
		return nil, err
	}
	return result, nil
}

// putVmcbSeg serializes the VMCB Segment protobuf representation into its ABI format.
func putVmcbSeg(v *spb.VmcbSeg, data []byte) error {
	if len(data) < SizeofVmcbSeg {
		return fmt.Errorf("data too small for VmcbSeg: %d < %d", len(data), SizeofVmcbSeg)
	}
	if v.Selector >= (1 << 16) {
		return fmt.Errorf("selector doesn't fit in 16 bits: %v", v.Selector)
	}
	if v.Attrib >= (1 << 16) {
		return fmt.Errorf("attrib doesn't fit in 16 bits: %v", v.Attrib)
	}
	binary.LittleEndian.PutUint16(data[0:2], uint16(v.Selector))
	binary.LittleEndian.PutUint16(data[2:4], uint16(v.Attrib))
	binary.LittleEndian.PutUint32(data[4:8], v.Limit)
	binary.LittleEndian.PutUint64(data[8:SizeofVmcbSeg], v.GetBase())
	return nil
}

func checkMbz(name string, data []byte, lo, hi int) error {
	if len(data) != hi-lo {
		return fmt.Errorf("field '%s' for byte range 0x%x:0x%x is not the same size: %d", name, lo, hi, len(data))
	}
	for i, b := range data {
		if b != 0 {
			return fmt.Errorf("reserved field '%s' has non-zero byte at index 0x%x (VMSA index 0x%x)", name, i, lo+i)
		}
	}
	return nil
}

// Ensure protobytes is all zeros, then set out[lo:hi] to all zeros.
func doReserved(name string, protobytes []byte, out []byte, lo, hi int) error {
	// Missing reserved fields are treated as present and the correct amount of zeroes.
	if len(protobytes) != 0 {
		if err := checkMbz(name, protobytes, lo, hi); err != nil {
			return err
		}
	}
	if len(out) < hi {
		return fmt.Errorf("range [0x%x, 0x%x) outside output size %d", lo, hi, len(out))
	}
	// The input data was zeros, so set output data to be zeros.
	for i := lo; i < hi; i++ {
		out[i] = 0
	}
	return nil
}

// Ensure proto64 is zero, then set data[lo:hi] to all zeros.
func doReserved64(name string, proto64 uint64, data []byte, lo, hi int) error {
	if hi-lo != 8 {
		return fmt.Errorf("range %x to %x is not 8 bytes", lo, hi)
	}
	if proto64 != 0 {
		return fmt.Errorf("uint64 field %s for byte range 0x:%x:0x%x is not zero", name, lo, hi)
	}
	// We've checked the input data is 0, so set the output data to 0.
	binary.LittleEndian.PutUint64(data[lo:hi], 0)
	return nil
}

func getOrCreateVmcbSeg(seg **spb.VmcbSeg) *spb.VmcbSeg {
	if *seg == nil {
		*seg = &spb.VmcbSeg{}
	}
	return *seg
}

// PutVmsa writes the VMCB Save area (VMSA) in its ABI format to data.
func PutVmsa(v *spb.VmcbSaveArea, data []byte) error {
	if len(data) < SizeofVmsa {
		return fmt.Errorf("data too small for VMSA: %d < %d", len(data), SizeofVmsa)
	}
	if err := putVmcbSeg(getOrCreateVmcbSeg(&v.Es), data[0:0x10]); err != nil {
		return fmt.Errorf("could not write VMSA.ES: %v", err)
	}
	if err := putVmcbSeg(getOrCreateVmcbSeg(&v.Cs), data[0x10:0x20]); err != nil {
		return fmt.Errorf("could not write VMSA.CS: %v", err)
	}
	if err := putVmcbSeg(getOrCreateVmcbSeg(&v.Ss), data[0x20:0x30]); err != nil {
		return fmt.Errorf("could not write VMSA.SS: %v", err)
	}
	if err := putVmcbSeg(getOrCreateVmcbSeg(&v.Ds), data[0x30:0x40]); err != nil {
		return fmt.Errorf("could not write VMSA.DS: %v", err)
	}
	if err := putVmcbSeg(getOrCreateVmcbSeg(&v.Fs), data[0x40:0x50]); err != nil {
		return fmt.Errorf("could not write VMSA.FS: %v", err)
	}
	if err := putVmcbSeg(getOrCreateVmcbSeg(&v.Gs), data[0x50:0x60]); err != nil {
		return fmt.Errorf("could not write VMSA.GS: %v", err)
	}
	if err := putVmcbSeg(getOrCreateVmcbSeg(&v.Gdtr), data[0x60:0x70]); err != nil {
		return fmt.Errorf("could not write VMSA.GDTR: %v", err)
	}
	if err := putVmcbSeg(getOrCreateVmcbSeg(&v.Ldtr), data[0x70:0x80]); err != nil {
		return fmt.Errorf("could not write VMSA.LDTR: %v", err)
	}
	if err := putVmcbSeg(getOrCreateVmcbSeg(&v.Idtr), data[0x80:0x90]); err != nil {
		return fmt.Errorf("could not write VMSA.IDTR: %v", err)
	}
	if err := putVmcbSeg(getOrCreateVmcbSeg(&v.Tr), data[0x90:0xA0]); err != nil {
		return fmt.Errorf("could not write VMSA.TR: %v", err)
	}
	if err := doReserved("reserved_1", v.Reserved_1, data, 0xA0, 0xCB); err != nil {
		return err
	}
	if v.Cpl >= (1 << 8) {
		return fmt.Errorf("cpl does not fit in 8 bits: 0x%x", v.Cpl)
	}
	data[0xCB] = uint8(v.Cpl)
	if err := doReserved("reserved_2", v.Reserved_2, data, 0xCC, 0xD0); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(data[0xD0:0xD8], v.Efer)
	if err := doReserved("reserved_3", v.Reserved_3, data, 0xD8, 0x140); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(data[0x140:0x148], v.Xss)
	binary.LittleEndian.PutUint64(data[0x148:0x150], v.Cr4)
	binary.LittleEndian.PutUint64(data[0x150:0x158], v.Cr3)
	binary.LittleEndian.PutUint64(data[0x158:0x160], v.Cr0)
	binary.LittleEndian.PutUint64(data[0x160:0x168], v.Dr7)
	binary.LittleEndian.PutUint64(data[0x168:0x170], v.Dr6)
	binary.LittleEndian.PutUint64(data[0x170:0x178], v.Rflags)
	binary.LittleEndian.PutUint64(data[0x178:0x180], v.Rip)
	if err := doReserved("reserved_4", v.Reserved_4, data, 0x180, 0x1D8); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(data[0x1D8:0x1E0], v.Rsp)
	if err := doReserved("reserved_5", v.Reserved_5, data, 0x1E0, 0x1F8); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(data[0x1F8:0x200], v.Rax)
	binary.LittleEndian.PutUint64(data[0x200:0x208], v.Star)
	binary.LittleEndian.PutUint64(data[0x208:0x210], v.Lstar)
	binary.LittleEndian.PutUint64(data[0x210:0x218], v.Cstar)
	binary.LittleEndian.PutUint64(data[0x218:0x220], v.Sfmask)
	binary.LittleEndian.PutUint64(data[0x220:0x228], v.KernelGsBase)
	binary.LittleEndian.PutUint64(data[0x228:0x230], v.SysenterCs)
	binary.LittleEndian.PutUint64(data[0x230:0x238], v.SysenterEsp)
	binary.LittleEndian.PutUint64(data[0x238:0x240], v.SysenterEip)
	binary.LittleEndian.PutUint64(data[0x240:0x248], v.Cr2)
	if err := doReserved("reserved_6", v.Reserved_6, data, 0x248, 0x268); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(data[0x268:0x270], v.GetGPat())
	binary.LittleEndian.PutUint64(data[0x270:0x278], v.GetDbgctl())
	binary.LittleEndian.PutUint64(data[0x278:0x280], v.BrFrom)
	binary.LittleEndian.PutUint64(data[0x280:0x288], v.BrTo)
	binary.LittleEndian.PutUint64(data[0x288:0x290], v.LastExcpFrom)
	binary.LittleEndian.PutUint64(data[0x290:0x298], v.LastExcpTo)

	// SEV-ES fields
	if err := doReserved("reserved_7", v.Reserved_7, data, 0x298, 0x2E8); err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(data[0x2E8:0x2EC], v.Pkru)
	if err := doReserved("reserved_7a", v.Reserved_7A, data, 0x2EC, 0x300); err != nil {
		return err
	}
	if err := doReserved64("reserved_8", v.Reserved_8, data, 0x300, 0x308); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(data[0x308:0x310], v.Rcx)
	binary.LittleEndian.PutUint64(data[0x310:0x318], v.Rdx)
	binary.LittleEndian.PutUint64(data[0x318:0x320], v.Rbx)
	if err := doReserved64("reserved_9", v.Reserved_9, data, 0x320, 0x328); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(data[0x328:0x330], v.Rbp)
	binary.LittleEndian.PutUint64(data[0x330:0x338], v.Rsi)
	binary.LittleEndian.PutUint64(data[0x338:0x340], v.Rdi)
	binary.LittleEndian.PutUint64(data[0x340:0x348], v.R8)
	binary.LittleEndian.PutUint64(data[0x348:0x350], v.R9)
	binary.LittleEndian.PutUint64(data[0x350:0x358], v.R10)
	binary.LittleEndian.PutUint64(data[0x358:0x360], v.R11)
	binary.LittleEndian.PutUint64(data[0x360:0x368], v.R12)
	binary.LittleEndian.PutUint64(data[0x368:0x370], v.R13)
	binary.LittleEndian.PutUint64(data[0x370:0x378], v.R14)
	binary.LittleEndian.PutUint64(data[0x378:0x380], v.R15)
	if err := doReserved("reserved_10", v.Reserved_10, data, 0x380, 0x390); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(data[0x390:0x398], v.SwExitCode)
	binary.LittleEndian.PutUint64(data[0x398:0x3A0], v.SwExitInfo_1)
	binary.LittleEndian.PutUint64(data[0x3A0:0x3A8], v.SwExitInfo_2)
	binary.LittleEndian.PutUint64(data[0x3A8:0x3B0], v.SwScratch)
	binary.LittleEndian.PutUint64(data[0x3B0:0x3B8], v.SevFeatures)
	if err := doReserved("reserved_11", v.Reserved_11, data, 0x3B8, 0x3F0); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(data[0x3E8:0x3F0], v.Xcr0)

	// SEV-ES fields that follow are all zero at launch.
	for i := 0x3F0; i < SizeofVmsa; i++ {
		data[i] = 0
	}

	return nil
}
