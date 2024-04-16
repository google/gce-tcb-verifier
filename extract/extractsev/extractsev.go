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

// Package extractsev provides utilities for extracting SEV-SNP endorsements.
package extractsev

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/gce-tcb-verifier/sev"
	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
)

var (
	// ErrNotInExtras is returned when the GCE endorsement is not in the certificate chain extras.
	ErrNotInExtras = errors.New("GCE endorsement not in certificate chain extras")
)

// familyIDObjectPrefix returns the gce_tcb_integrity GCS object name prefix to use for a
// firmware assigned familyID.
func familyIDObjectPrefix(familyID string) string {
	// While certificates are delivered through the auxblob, the key will be GCEFwCertGUID. It can
	// be helpful to understand the familyID the same way when you're expecting a particular family.
	if familyID == sev.GCEUefiFamilyID || familyID == sev.GCEFwCertGUID {
		return "ovmf_x64_csm"
	}
	return "unknown"
}

// gceTcbObjectPath returns the object path within the gce_tcb_integrity GCS bucket that
// corresponds to the given SEV-SNP attestation report measurement.
func gceTcbObjectPath(measurement []byte) string {
	return fmt.Sprintf("sevsnp/%s.binarypb", hex.EncodeToString(measurement))
}

// GceTcbObjectName returns the expected object name within a GCS bucket for a firmware
// measured for SEV-SNP.
func GceTcbObjectName(familyID string, measurement []byte) string {
	return fmt.Sprintf("%s/%s", familyIDObjectPrefix(familyID), gceTcbObjectPath(measurement))
}

// FromAttestation returns the contents of the SEV-SNP auxblob entry for the GCE UEFI endorsement.
func FromAttestation(at *spb.Attestation) ([]byte, error) {
	if blob, ok := at.GetCertificateChain().GetExtras()[sev.GCEFwCertGUID]; ok {
		return blob, nil
	}
	return nil, ErrNotInExtras
}

// FromCertTable returns the contents of the certificate table entry for the GCE UEFI endorsement.
func FromCertTable(table []byte) ([]byte, error) {
	t := new(abi.CertTable)
	if err := t.Unmarshal(table); err != nil {
		return nil, err
	}
	return t.GetByGUIDString(sev.GCEFwCertGUID)
}
