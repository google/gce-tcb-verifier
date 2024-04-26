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

	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/go-sev-guest/abi"
	sgpb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/uuid"
)

const (
	// GCEUefiFamilyID is the UUID GCE uses for all its SEV-SNP firmwares.
	GCEUefiFamilyID = "f73a6949-e8f3-473b-9553-e40e056fa3a2"
	// GCEFwCertGUID is the UUID that GCE uses to provide the serialized launch endorsement to a
	// SEV-SNP guest in the certificate table.
	GCEFwCertGUID = "9f4116cd-c503-4f5a-8f6f-fb68882f4ce2"
)

// SnpEndorsementRequest encapsulates all AMD-specific information needed to endorse a UEFI binary
// for SEV-SNP.
type SnpEndorsementRequest struct {
	// Svn is the image's security version number.
	Svn uint32
	// FamilyID is in some GUID format, e.g., xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	// If unset, defaults to GCE guest UEFI family GUID.
	FamilyID string
	// ImageID is in some GUID format. Should uniquely identify the bits of the image.
	ImageID string
	// LaunchVmsas is the number of VMSAs to consider when creating endorsed measurements. If unset,
	// will generate all supported VMSAs at launch in GCE.
	LaunchVmsas uint32
	// Product is the AMD product that will generate attestations for this measurement.
	Product sgpb.SevProduct_SevProductName
}

// Guests can run on multiple sockets.
// Debug is not allowed.
// Migration agents are allowed.
// SMT is allowed.
// ABI minimum version is currently 0.
var prodPolicy = abi.SnpPolicyToBytes(abi.SnpPolicy{
	ABIMinor:     0,
	ABIMajor:     0,
	SMT:          true,
	MigrateMA:    true,
	Debug:        false,
	SingleSocket: false,
})

// AllSupportedVmsaCounts is the number of VMSAs we expect to see measured in GCE for any particular
// SEV-SNP VM. 1 is included for AP boot case when VMSAs aren't all created at launch. All other
// numbers come from
// ```
// gcloud compute machines-types list | grep n2d- | awk '{print $3}' | sort -g | uniq
// ```
var AllSupportedVmsaCounts = []uint32{1, 2, 4, 8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 224, 240}

func vmsaCounts(snpRequest *SnpEndorsementRequest) []uint32 {
	// By not providing a specific VMSA count, we interpret that as we should generate all LDs that
	// we should expect to see from the available vCPU counts on GCE. We should only need this until
	// the GHCB spec and KVM are changed to not needlessly measure > 1 VMSA at launch.
	if snpRequest.LaunchVmsas == 0 {
		return AllSupportedVmsaCounts
	}
	return []uint32{snpRequest.LaunchVmsas}
}

func generateAllPossibleLDs(uefi []byte, snpRequest *SnpEndorsementRequest) (map[uint32][]byte, error) {
	options := LaunchOptionsDefault()
	options.Product = snpRequest.Product

	result := make(map[uint32][]byte)
	for _, count := range vmsaCounts(snpRequest) {
		options.Vcpus = int(count)
		ld, err := LaunchDigest(options, uefi)
		if err != nil {
			return nil, err
		}
		result[count] = ld
	}
	return result, nil
}

func generateVMSevSnp(lds map[uint32][]byte, snpRequest *SnpEndorsementRequest) *epb.VMSevSnp {
	familyID := uuid.MustParse(snpRequest.FamilyID)
	imageID := uuid.MustParse(snpRequest.ImageID)

	return &epb.VMSevSnp{
		Svn:          snpRequest.Svn,
		FamilyId:     familyID[:],
		ImageId:      imageID[:],
		Policy:       prodPolicy,
		Measurements: lds,
		// Certs will be filled in at signing time.
	}
}

func canonicalizeRequest(snpRequest *SnpEndorsementRequest) error {
	// Set ID guids in the request to defaults if they aren't set.
	if snpRequest.FamilyID == "" {
		snpRequest.FamilyID = GCEUefiFamilyID
	}
	if snpRequest.ImageID == "" {
		imageGUID, err := uuid.NewRandom()
		if err != nil {
			return err
		}
		snpRequest.ImageID = imageGUID.String()
	}

	// Validate the request.
	if _, err := uuid.Parse(snpRequest.FamilyID); err != nil {
		return fmt.Errorf("could not parse family_id: %v", err)
	}
	if _, err := uuid.Parse(snpRequest.ImageID); err != nil {
		return fmt.Errorf("could not parse image_id: %v", err)
	}
	return nil
}

// UnsignedSnp returns the SevSnp component of a GoldenMeasurement for a given UEFI.
func UnsignedSnp(uefi []byte, snpRequest *SnpEndorsementRequest) (*epb.VMSevSnp, error) {
	if err := canonicalizeRequest(snpRequest); err != nil {
		return nil, err
	}

	// Create the basis for all endorsements.
	lds, err := generateAllPossibleLDs(uefi, snpRequest)
	if err != nil {
		return nil, err
	}

	return generateVMSevSnp(lds, snpRequest), nil
}
