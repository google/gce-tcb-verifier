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

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/gce-tcb-verifier/ovmf/abi"
	opb "github.com/google/gce-tcb-verifier/proto/ovmf"
	"github.com/google/gce-tcb-verifier/testing/fakeovmf"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

type OvmfSevDataTest struct {
	// Buffer for SEV-ES test cases.
	sevEsBuffer [0x64]byte
	// Buffer for SEV-ES and SNP test case with GUID Table in Firmware.
	sevGUIDTableBuffer [0x512]byte

	// A slice of either of the above.
	firmwareWithGUIDTable []byte
}

const sizeofSevGUIDTableBuffer = 0x512

func SetupOvmfSevDataTest() (*OvmfSevDataTest, error) {
	result := &OvmfSevDataTest{}
	if err := fakeovmf.InitializeSevResetBlock(result.sevEsBuffer[:], abi.FwGUIDTableEndOffset, fakeovmf.SevEsAddrVal); err != nil {
		return nil, err
	}
	if err := fakeovmf.InitializeSevGUIDTable(result.sevGUIDTableBuffer[:], abi.FwGUIDTableEndOffset, fakeovmf.SevEsAddrVal, fakeovmf.DefaultSnpSections()); err != nil {
		return nil, err
	}
	result.firmwareWithGUIDTable = result.sevGUIDTableBuffer[:]
	return result, nil
}

func TestNoSevOk(t *testing.T) {
	f, err := SetupOvmfSevDataTest()
	if err != nil {
		t.Fatal(err)
	}
	data := SevData{SevEs: false, SevSnp: false}

	if err := data.ExtractFromFirmware(f.firmwareWithGUIDTable); err != nil {
		t.Errorf("%v.ExtractFromFirmware(%v) errored unexpectedly: %v", data, f.firmwareWithGUIDTable, err)
	}
	// Check that initialization above doesn't change the behavior.
	if err := data.ExtractFromFirmware(f.firmwareWithGUIDTable); err != nil {
		t.Errorf("%v.ExtractFromFirmware(%v) errored unexpectedly: %v", data, f.firmwareWithGUIDTable, err)
	}
}

func TestSnpWithoutEs(t *testing.T) {
	f, err := SetupOvmfSevDataTest()
	if err != nil {
		t.Fatal(err)
	}
	data := SevData{SevEs: false, SevSnp: true}

	want := "cannot use SEV-SNP without SEV-ES"
	if err := data.ExtractFromFirmware(f.firmwareWithGUIDTable); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%v.ExtractFromFirmware(%v) = %v, not an error containing \"%s\"", data, f.firmwareWithGUIDTable, err, want)
	}
}

func TestExtractSevEsTwice(t *testing.T) {
	f, err := SetupOvmfSevDataTest()
	if err != nil {
		t.Fatal(err)
	}
	data := SevData{SevEs: true, SevSnp: false}
	if err := data.ExtractFromFirmware(f.firmwareWithGUIDTable); err != nil {
		t.Errorf("%v.ExtractFromFirmware(%v) errored unexpectedly: %v", data, f.firmwareWithGUIDTable, err)
	}
	want := "SEV-ES Reset block already set"
	if err := data.ExtractFromFirmware(f.firmwareWithGUIDTable); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%v.ExtractFromFirmware(%v) = %v, not an error containing \"%s\"", data, f.firmwareWithGUIDTable, err, want)
	}
}

func TestUnextractedSevEs(t *testing.T) {
	data := SevData{SevEs: false, SevSnp: false}
	want := "no SEV-ES reset block available"
	if got, err := data.SevEsResetBlock(); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%v.SevEsResetBlock() = %v, %v, not an error containing \"%s\"", data, got, err, want)
	}
}

func TestUnextractedSections(t *testing.T) {
	data := SevData{SevEs: false, SevSnp: false}
	want := "SEV OVMF metadata not found"
	if got, err := data.SnpMetadataSections(); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%v.SnpMetadataSections() = %v, %v, not an error containing \"%s\"", data, got, err, want)
	}
}

func unorderedSectionsEqual(a, b []abi.SevMetadataSection) bool {
	toBag := func(ss []abi.SevMetadataSection) map[abi.SevMetadataSection]int {
		m := make(map[abi.SevMetadataSection]int)
		for _, s := range ss {
			m[s] = 1 + m[s]
		}
		return m
	}
	abag := toBag(a)
	bbag := toBag(b)
	if len(abag) != len(bbag) {
		return false
	}
	for s := range abag {
		if abag[s] != bbag[s] {
			return false
		}
	}
	return true
}

func TestExtractSevSnp(t *testing.T) {
	f, err := SetupOvmfSevDataTest()
	if err != nil {
		t.Fatal(err)
	}
	data := SevData{SevEs: true, SevSnp: true}
	if err := data.ExtractFromFirmware(f.firmwareWithGUIDTable); err != nil {
		t.Errorf("%v.ExtractFromFirmware(%v) errored unexpectedly: %v", data, f.firmwareWithGUIDTable, err)
	}
	sections, err := data.SnpMetadataSections()
	if err != nil {
		t.Errorf("%v.SnpMetadataSections() errored unexpectedly: %v", data, err)
	}
	want := []abi.SevMetadataSection{
		{
			Address: fakeovmf.SevSnpValidatedStartAddr,
			Length:  fakeovmf.SevSnpValidatedLength,
			Kind:    abi.SevUnmeasuredSection},
		{
			Address: fakeovmf.SevSnpCpuidAddr,
			Length:  abi.PageSize,
			Kind:    abi.SevCpuidSection,
		},
		{
			Address: fakeovmf.SevSnpSecretAddr,
			Length:  abi.PageSize,
			Kind:    abi.SevSecretSection,
		},
	}
	if !unorderedSectionsEqual(sections, want) {
		t.Errorf("%v.SnpMetadataSections() = %v, want (in any order) %v", data, sections, want)
	}
}

func TestSnpMetadataSections(t *testing.T) {
	type expectation struct {
		wantErr  bool
		anyError []string
		values   []abi.SevMetadataSection
	}
	contains := func(str string) expectation {
		return expectation{wantErr: true, anyError: []string{str}}
	}
	anyOf := func(strs []string) expectation {
		return expectation{wantErr: true, anyError: strs}
	}
	values := func(v []abi.SevMetadataSection) expectation { return expectation{values: v} }
	match := func(e *expectation, v []abi.SevMetadataSection, err error) (string, bool) {
		if e.wantErr {
			if err == nil {
				return fmt.Sprintf("succeeded unexpectedly. Want any error in %v", e.anyError), false
			}
			str := err.Error()
			for _, want := range e.anyError {
				if strings.Contains(str, want) {
					return "", true
				}
			}
			if len(e.anyError) == 1 {
				return fmt.Sprintf("= %v, %v, not an error containing \"%s\"", v, err, e.anyError[0]), false
			}
			return fmt.Sprintf("= %v, %v, not an error containing any of %v", v, err, e.anyError), false
		}
		if err != nil {
			return fmt.Sprintf("errored unexpectedly: %v", err), false
		}
		if !unorderedSectionsEqual(v, e.values) {
			return fmt.Sprintf("= %v, want (in any order) %v", v, e.values), false
		}
		return "", true
	}
	type testCase struct {
		name        string
		setup       func(f *OvmfSevDataTest) error
		want        expectation
		wantExtract expectation
	}
	initWith := func(sections []abi.SevMetadataSection) func(f *OvmfSevDataTest) error {
		return func(f *OvmfSevDataTest) error {
			if err := fakeovmf.InitializeSevGUIDTable(f.sevGUIDTableBuffer[:], abi.FwGUIDTableEndOffset, fakeovmf.SevEsAddrVal, sections); err != nil {
				return fmt.Errorf("InitializeSevGUIDTable(%v, %v, %v, %v) = %s", f.sevGUIDTableBuffer, abi.FwGUIDTableEndOffset, fakeovmf.SevEsAddrVal, sections, err)
			}
			return nil
		}
	}
	tests := []testCase{
		{
			name: "ExtractSevOvmfMetadataValidTableWithGUID",
			want: values(fakeovmf.DefaultSnpSections()),
		},
		{
			name:  "ExtraSecretSectionDisallowed",
			setup: initWith(append(fakeovmf.DefaultSnpSections(), fakeovmf.SnpSecretSection(0x9000))),
			want:  contains("expected only 1 section of type OVMF_SECTION_TYPE_SNP_SECRETS. Previous section at address 0xff004000 conflicts with extra section at address 0x9000"),
		},
		{
			name: "SevSnpBadSize",
			setup: initWith([]abi.SevMetadataSection{
				fakeovmf.SnpValidatedSection(fakeovmf.SevSnpValidatedStartAddr, fakeovmf.SevSnpValidatedLength-1),
				fakeovmf.SnpCpuidSection(fakeovmf.SevSnpValidatedStartAddr + fakeovmf.SevSnpValidatedLength),
				fakeovmf.SnpSecretSectionDefault()}),
			want: contains("section OVMF_SECTION_TYPE_SNP_SEC_MEM has length that's not a positive multiple of a 4K page size: 0xfff"),
		},
		{
			name: "SevSnp0Size",
			setup: initWith([]abi.SevMetadataSection{
				fakeovmf.SnpValidatedSection(fakeovmf.SevSnpValidatedStartAddr, 0),
				fakeovmf.SnpCpuidSection(fakeovmf.SevSnpValidatedStartAddr + fakeovmf.SevSnpValidatedLength),
				fakeovmf.SnpSecretSectionDefault(),
			}),
			want: contains("section OVMF_SECTION_TYPE_SNP_SEC_MEM has length that's not a positive multiple of a 4K page size: 0x0"),
		},
		{
			name: "OverlappingSevSnp",
			setup: initWith([]abi.SevMetadataSection{fakeovmf.SnpValidatedSection(fakeovmf.SevSnpValidatedStartAddr,
				fakeovmf.SevSnpValidatedLength+abi.PageSize),
				fakeovmf.SnpCpuidSection(fakeovmf.SevSnpValidatedStartAddr + fakeovmf.SevSnpValidatedLength),
				fakeovmf.SnpSecretSectionDefault()}),
			want: contains("SEV section OVMF_SECTION_TYPE_SNP_SEC_MEM: [0xff001000-0xff003000] overlaps with OVMF_SECTION_TYPE_CPUID: [0xff002000-0xff003000]"),
		},
		{
			name: "OverlappingSevSnpUnknown",
			setup: initWith([]abi.SevMetadataSection{
				fakeovmf.SnpValidatedSection(fakeovmf.SevSnpValidatedStartAddr,
					fakeovmf.SevSnpValidatedLength+abi.PageSize),
				fakeovmf.SnpCpuidSectionDefault(), fakeovmf.SnpSecretSectionDefault(),
				// Add an extra page of unknown type to see what that renders as.
				{
					Address: fakeovmf.SevSnpValidatedStartAddr + fakeovmf.SevSnpValidatedLength,
					Length:  abi.PageSize,
					Kind:    0x420,
				},
			}),
			want: contains("SEV section OVMF_SECTION_TYPE_SNP_SEC_MEM: [0xff001000-0xff003000] overlaps with [unknown SNP metadata section type: 0x420]: [0xff002000-0xff003000]"),
		},
		{
			name: "WeirdOrder",
			setup: initWith([]abi.SevMetadataSection{
				fakeovmf.SnpValidatedSectionDefaultLength(fakeovmf.SevSnpSecretAddr),
				fakeovmf.SnpCpuidSection(fakeovmf.SevSnpValidatedStartAddr),
				fakeovmf.SnpSecretSection(fakeovmf.SevSnpCpuidAddr),
			}),
			want: values([]abi.SevMetadataSection{
				fakeovmf.SnpValidatedSectionDefaultLength(fakeovmf.SevSnpSecretAddr),
				fakeovmf.SnpCpuidSection(fakeovmf.SevSnpValidatedStartAddr),
				fakeovmf.SnpSecretSection(fakeovmf.SevSnpCpuidAddr),
			}),
		},
		{
			name: "ExtractSnpOverlapWithValidAfterCpuid",
			setup: initWith([]abi.SevMetadataSection{
				fakeovmf.SnpValidatedSection(fakeovmf.SevSnpCpuidAddr, fakeovmf.SevSnpValidatedLength),
				fakeovmf.SnpCpuidSection(fakeovmf.SevSnpValidatedStartAddr),
				fakeovmf.SnpSecretSection(fakeovmf.SevSnpCpuidAddr),
			}),
			want: anyOf([]string{
				"SEV section OVMF_SECTION_TYPE_SNP_SEC_MEM: [0xff003000-0xff004000] overlaps with OVMF_SECTION_TYPE_SNP_SECRETS: [0xff003000-0xff004000]",
				"SEV section OVMF_SECTION_TYPE_SNP_SECRETS: [0xff003000-0xff004000] overlaps with OVMF_SECTION_TYPE_SNP_SEC_MEM: [0xff003000-0xff004000]",
			}),
		},
		{
			name: "MissingSecrets",
			setup: initWith([]abi.SevMetadataSection{
				fakeovmf.SnpValidatedSectionDefault(),
				fakeovmf.SnpCpuidSectionDefault(),
				/* No secret section */
			}),
			want: contains("no secret page"),
		},
		{
			name: "MissingValidatedStart",
			setup: initWith([]abi.SevMetadataSection{
				/* No validated section */
				fakeovmf.SnpCpuidSectionDefault(),
				fakeovmf.SnpSecretSectionDefault(),
			}),
			want: contains("no proper pre-validated addresses"),
		},
		{
			name: "MissingCpuid",
			setup: initWith([]abi.SevMetadataSection{
				fakeovmf.SnpValidatedSectionDefault(),
				/* No cpuid section */
				fakeovmf.SnpSecretSectionDefault(),
			}),
			want: contains("no CPUID page"),
		},
		{
			name: "ExtractSevOvmfMetadataLengthTooLarge",
			setup: func(f *OvmfSevDataTest) error {
				// This test needs a firmware image with valid GUID table. It will make
				// modifications to the SEV OVMF Metadata header which the offset in the
				// GUIDed table points to. Since the test data has specific offsets
				// hardcoded we can generate a correct firmware and simply make the changes
				// in the header using byte manipulation (the SEV metadata is expected to start at 0).
				metadata := abi.SevMetadataFromBytes(f.sevGUIDTableBuffer[:])
				// In order to check the length exceeding the size of the firmware we also
				// need to increase the amount of sections. Otherwise we will hit the case
				// covered by ExtractSevOvmfMetadataLengthSectionsMismatch.
				newSectionsCount := uint32(0x1000)
				metadata.Length = abi.SizeofSevMetadata + newSectionsCount*abi.SizeofSevMetadataSection
				metadata.Sections = newSectionsCount
				return metadata.Put(f.firmwareWithGUIDTable[:])
			},
			wantExtract: contains("SEV OVMF Metadata Offset is not large enough to contain the metadata: 1298 < 49168"),
		},
		{
			name: "ExtractSevOvmfMetadataOffsetTooLarge",
			setup: func(f *OvmfSevDataTest) error {
				return fakeovmf.MutateSevMetadataOffsetBlock(f.sevGUIDTableBuffer[:], func(block *abi.MetadataOffset) error {
					// We set the SEV OVMF Metadata offset to exceed the size of the whole
					// firmware.
					block.Offset = sizeofSevGUIDTableBuffer + 1
					return nil
				})
			},
			wantExtract: contains("firmware is too small: found size 1298 < 1299"),
		},
		{
			name: "ExtractSevOvmfMetadataNotFound",
			setup: func(f *OvmfSevDataTest) error {
				// This test needs a firmware image with valid GUID table with no SNP
				// boot block.
				return fakeovmf.MutateSevMetadataOffsetBlock(f.sevGUIDTableBuffer[:], func(block *abi.MetadataOffset) error {
					var zeroGUID uuid.UUID
					// Change the GUID of the SEV Metadata entry to cause the GUID mismatch.
					block.GUIDEntry.GUID = zeroGUID
					return nil
				})
			},
			wantExtract: contains(fmt.Sprintf("no matching block found for GUID: %s", abi.SevMetadataOffsetGUID)),
		},
		{
			name: "ExtractSevOvmfMetadataBadSignature",
			// This test needs a firmware image with valid GUID table. It will make
			// modifications to the SEV OVMF Metadata header which the offset in the
			// GUIDed table points to. Since the test data has specific offsets
			// hardcoded we can generate a correct firmware and simply make the changes
			// in the header using memcpy (the SEV metadata is expected to start at 0).
			setup: func(f *OvmfSevDataTest) error {
				metadata := abi.SevMetadataFromBytes(f.firmwareWithGUIDTable)
				metadata.Signature = 0x1234
				metadata.Put(f.firmwareWithGUIDTable)
				return nil
			},
			wantExtract: contains("signature of the SEV memory offset is incorrect: 4660"),
		},
		{
			name: "ExtractSevOvmfMetadataLengthSectionsMismatch",
			// This test needs a firmware image with valid GUID table. It will make
			// modifications to the SEV OVMF Metadata header which the offset in the
			// GUIDed table points to. Since the test data has specific offsets
			// hardcoded we can generate a correct firmware and simply make the changes
			// in the header using memcpy (the SEV metadata is expected to start at 0).
			setup: func(f *OvmfSevDataTest) error {
				metadata := abi.SevMetadataFromBytes(f.firmwareWithGUIDTable)
				metadata.Length = 0x1000
				metadata.Put(f.firmwareWithGUIDTable)
				return nil
			},
			wantExtract: contains("mismatch between SEV memory offset length: 4096 and SEV metadata offset sections count: 3"),
		},
	}
	for _, tc := range tests {
		f, err := SetupOvmfSevDataTest()
		if err != nil {
			t.Fatal(err)
		}
		data := SevData{SevEs: true, SevSnp: true}
		if tc.setup != nil {
			if err := tc.setup(f); err != nil {
				t.Errorf("%s test data transform failed unexpectedly: %v", tc.name, err)
				continue
			}
		}
		err = data.ExtractFromFirmware(f.firmwareWithGUIDTable)
		if s, ok := match(&tc.wantExtract, nil, err); !ok {
			t.Errorf("%s: %v.ExtractFromFirmware(%v) %s", tc.name, data, f.firmwareWithGUIDTable, s)
		}
		if !tc.wantExtract.wantErr {
			v, err := data.SnpMetadataSections()
			if s, ok := match(&tc.want, v, err); !ok {
				t.Errorf("%s: %v.SnpMetadataSections() %s", tc.name, data, s)
			}
		}
	}
}

func TestExtractSevEsResetBlockValidTableWithGUID(t *testing.T) {
	f, err := SetupOvmfSevDataTest()
	if err != nil {
		t.Fatal(err)
	}
	want := fakeovmf.GenerateExpectedSevResetBlockDefault()
	data := SevData{SevEs: true, SevSnp: false}
	if err := data.ExtractFromFirmware(f.firmwareWithGUIDTable); err != nil {
		t.Errorf("%v.ExtractFromFirmware(%v) errored unexpectedly: %v", data, f.firmwareWithGUIDTable, err)
	}
	got, err := data.SevEsResetBlock()
	if err != nil {
		t.Errorf("%v.SevEsResetBlock() errored unexpectedly: %v", data, err)
	}
	if !proto.Equal(got, want) {
		t.Errorf("%v.SevEsResetBlock() = %v, want %v", data, got, want)
	}
}

func TestExtractSevEsResetBlockNotFound(t *testing.T) {
	f, err := SetupOvmfSevDataTest()
	if err != nil {
		t.Fatal(err)
	}
	if err := fakeovmf.MutateSevEsResetBlock(f.sevGUIDTableBuffer[:], func(block *opb.SevEsResetBlock, _ int) error {
		// Change the GUID entry of SEV reset block to cause the GUID mismatch.
		var zeroGUID uuid.UUID
		block.Guid = zeroGUID[:]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	data := SevData{SevEs: true, SevSnp: false}
	want := fmt.Sprintf("no matching block found for GUID: %s", abi.SevEsResetBlockGUID)
	if err := data.ExtractFromFirmware(f.firmwareWithGUIDTable); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%v.ExtractFromFirmware(%v) = %v, want an error containing \"%s\"", data, f.firmwareWithGUIDTable, err, want)
	}
}

func TestExtractSevEsResetBlockLengthMismatch(t *testing.T) {
	f, err := SetupOvmfSevDataTest()
	if err != nil {
		t.Fatal(err)
	}
	// This test needs a firmware image with valid GUID table with wrong SEV-ES
	// reset block size.
	if err := fakeovmf.MutateSevEsResetBlock(f.sevGUIDTableBuffer[:], func(block *opb.SevEsResetBlock, _ int) error {
		// Change the size of SEV-ES reset entry to spawn the reset of the GUIDed table.
		block.Size = block.Size + abi.SizeofMetadataOffset
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	data := SevData{SevEs: true, SevSnp: false}
	want := fmt.Sprintf("mismatch with GUID block size, GUID: %s", abi.SevEsResetBlockGUID)
	if err := data.ExtractFromFirmware(f.firmwareWithGUIDTable); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%v.ExtractFromFirmware(%v) = %v, want an error containing \"%s\"", data, f.firmwareWithGUIDTable, err, want)
	}
}

func TestExtractSevOvmfMetadataOffsetMissing(t *testing.T) {
	f, err := SetupOvmfSevDataTest()
	if err != nil {
		t.Fatal(err)
	}
	if err := fakeovmf.MutateSevEsResetBlock(f.sevGUIDTableBuffer[:], func(resetEntry *opb.SevEsResetBlock, resetBlockOffset int) error {
		sevMetadataOffsetSlice := f.sevGUIDTableBuffer[resetBlockOffset-abi.SizeofMetadataOffset : resetBlockOffset]
		sevMetadataOffset, err := abi.MetadataOffsetFromBytes(sevMetadataOffsetSlice)
		if err != nil {
			return err
		}
		// Replace the GUID of reset block with that of the SEV Metadata and the change the size of the
		// reset block to span the rest of the GUIDed table to cause the SEV Metadata size mismatch.
		// This is done to ensure that call to GetFwGUIDToBlockMap properly.
		// Other alternative is to just modify the guidBlockMap directly.
		resetEntry.Guid = sevMetadataOffset.GUIDEntry.GUID[:]
		resetEntry.Size = resetEntry.Size + abi.SizeofMetadataOffset
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}

	guidBlockMap, err := GetFwGUIDToBlockMap(f.firmwareWithGUIDTable)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("mismatch with GUID block size, GUID: %s", abi.SevMetadataOffsetGUID)
	if got, err := extractSevOvmfMetadata(guidBlockMap, f.firmwareWithGUIDTable); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("extractSevOvmfMetadata(%v, %v) = %v, %v, expect an error containing \"%s\"", guidBlockMap, f.firmwareWithGUIDTable, got, err, want)
	}
}

func TestGetRipAndCsBaseFromSevEsResetBlock(t *testing.T) {
	f, err := SetupOvmfSevDataTest()
	if err != nil {
		t.Fatal(err)
	}
	want := fakeovmf.GenerateExpectedSevResetBlockDefault()
	data := SevData{SevEs: true, SevSnp: false}
	if err := data.ExtractFromFirmware(f.firmwareWithGUIDTable); err != nil {
		t.Errorf("%v.ExtractFromFirmware(%v) errored unexpectedly: %v", data, f.firmwareWithGUIDTable, err)
	}
	block, err := data.SevEsResetBlock()
	if err != nil {
		t.Errorf("%v.SevEsResetBlock() errored unexpectedly: %v", data, err)
	}
	ripMask := uint64(0x0000ffff)
	csBaseMask := uint64(0xffff0000)
	rip, csbase, err := GetRipAndCsBaseFromSevEsResetBlock(block)
	if err != nil {
		t.Errorf("GetRipAndCsBaseFromSevEsResetBlock(%v) errored unexpectedly: %v", block, err)
	}
	wantRip := (uint64(want.Addr) & ripMask)
	wantCsbase := (uint64(want.Addr) & csBaseMask)
	if rip != wantRip || csbase != wantCsbase {
		t.Errorf("GetRipAndCsBaseFromSevEsResetBlock(%v) = %v, %v, want %v, %v", block, rip, csbase, wantRip, wantCsbase)
	}
}
