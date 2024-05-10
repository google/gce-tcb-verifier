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

// Package verify provides functions to check an endorsement against a UEFI binary.
package verify

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/gce-tcb-verifier/extract/extractsev"
	"github.com/google/gce-tcb-verifier/sev"
	"github.com/google/go-sev-guest/abi"
	"google.golang.org/protobuf/proto"

	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
)

var (
	// ErrNoSevSnp is returned when SNP verification is requested but is not present in the
	// endorsement.
	ErrNoSevSnp = errors.New("golden measurement does not have SEV-SNP information")
	// ErrNoSevSnpMeasurements is returned when a measurement verification is requested but the golden
	// measurement does not have any SEV-SNP measurements.
	ErrNoSevSnpMeasurements = errors.New("golden measurement does not have SEV-SNP measurements")
	// ErrNoEndorsementCert is returned when a launch endorsement's Cert field is empty.
	ErrNoEndorsementCert = errors.New("endorsement certificate is empty")
)

const gcsBaseURL = "https://storage.googleapis.com"

// SNPOptions are SEV-SNP technology-specific validation options to check against the endorsement.
type SNPOptions struct {
	// measurement is an optional SEV-SNP measurement to check against the endorsement's list of
	// measurements.
	Measurement []byte
	// ExpectedLaunchVMSAs is an optional (0 ignored) number of expected VMSAs to have launched with.
	// The effect is that the measurement is compared against only the measurement computed for this
	// VMSA count. It is an error for ExpectedLaunchVMSAs to be non-zero while Measurement is nil.
	ExpectedLaunchVMSAs uint32
}

// HTTPSGetter represents the ability to fetch data from the internet from an HTTP URL.
// Used particularly for fetching certificates.
type HTTPSGetter interface {
	Get(url string) ([]byte, error)
}

// GceTcbURL returns the URL to the named object within the gce-tcb-integrity storage bucket.
func GceTcbURL(objectName string) string {
	return fmt.Sprintf("%s/gce_tcb_integrity/%s", gcsBaseURL, objectName)
}

// Options provides validation options when checking a launch endorsement
type Options struct {
	SNP                *SNPOptions
	RootsOfTrust       *x509.CertPool
	ExpectedUefiSha384 []byte
	Now                time.Time
	Getter             HTTPSGetter
}

// SNPValidateFunc returns a validation function that can be used with go-sev-guest on an
// SEV-SNP attestation report.
func SNPValidateFunc(opts *Options) func(*spb.Attestation, []byte) error {
	return SNPFamilyValidateFunc(sev.GCEUefiFamilyID, opts)
}

// SNPFamilyValidateFunc returns a validation function that can be used with go-sev-guest on an
// SEV-SNP attestation report given an expected familyID.
func SNPFamilyValidateFunc(familyID string, opts *Options) func(*spb.Attestation, []byte) error {
	if opts.SNP == nil {
		return func(*spb.Attestation, []byte) error {
			return nil
		}
	}
	return func(attestation *spb.Attestation, serializedEndorsement []byte) error {
		if attestation == nil {
			return fmt.Errorf("attestation is nil")
		}
		measurement := attestation.GetReport().GetMeasurement()
		if len(measurement) != abi.MeasurementSize {
			return fmt.Errorf("measurement size is %d, want %d", len(measurement), abi.MeasurementSize)
		}
		if serializedEndorsement == nil {
			if opts.Getter == nil {
				return fmt.Errorf("endorsement getter is nil")
			}
			blob, err := opts.Getter.Get(GceTcbURL(extractsev.GceTcbObjectName(familyID, measurement)))
			if err != nil {
				return fmt.Errorf("could not fetch endorsement: %v", err)
			}
			serializedEndorsement = blob

		}
		opts.SNP.Measurement = measurement
		return Endorsement(serializedEndorsement, opts)
	}
}

// Endorsement validates the signature and some contents of the serialized launch endorsement
// message.
func Endorsement(serializedEndorsement []byte, opts *Options) error {
	endorsement := &epb.VMLaunchEndorsement{}
	if err := proto.Unmarshal(serializedEndorsement, endorsement); err != nil {
		return fmt.Errorf("could not unmarshal VM launch endorsement: %v", err)
	}
	return EndorsementProto(endorsement, opts)
}

// EndorsementProto validates the signature and some contents of the launch endorsement message.
func EndorsementProto(endorsement *epb.VMLaunchEndorsement, opts *Options) error {
	golden := &epb.VMGoldenMeasurement{}
	if err := proto.Unmarshal(endorsement.SerializedUefiGolden, golden); err != nil {
		return fmt.Errorf("could not unmarshal golden measurement: %v", err)
	}

	if golden.ClSpec == 0 && len(golden.Commit) == 0 {
		return fmt.Errorf("missing provenance information")
	}

	// Before checking the signature of the golden measurement, first check the signer key's
	// certificate.
	cert, err := CheckCertificate(golden.Cert, opts.RootsOfTrust, opts.Now)
	if err != nil {
		return fmt.Errorf("endorsement certificate is invalid: %v", err)
	}

	// Check the endorsement signature.  The algorithm of the key is known a priori to be SHA256 with
	// RSA-PSS.
	if err := cert.CheckSignature(x509.SHA256WithRSAPSS, endorsement.SerializedUefiGolden,
		endorsement.GetSignature()); err != nil {
		return fmt.Errorf("endorsement signature is invalid: %v", err)
	}

	// Check the UEFI binary digest before checking technology measurements.
	if len(opts.ExpectedUefiSha384) != 0 && !bytes.Equal(opts.ExpectedUefiSha384, golden.Digest) {
		return fmt.Errorf("digest for UEFI %s does not match endorsement %s",
			hex.EncodeToString(opts.ExpectedUefiSha384), hex.EncodeToString(golden.Digest))
	}

	if opts.SNP != nil {
		if err := SNP(golden, opts.SNP); err != nil {
			return fmt.Errorf("endorsement did not validate with SEV-SNP options: %v", err)
		}
	}

	// We don't double-check the measure computations since we're trusting the signer to have gotten
	// those right. We do however check a given measurement against the endorsement. This process
	// may change as we bring user-specified data into the launch measurement.
	return nil
}

// SNP returns an error if the golden measurement violates SNP-specific validation options.
func SNP(golden *epb.VMGoldenMeasurement, opts *SNPOptions) error {
	if golden.SevSnp == nil {
		return ErrNoSevSnp
	}
	snp := golden.SevSnp
	if opts.ExpectedLaunchVMSAs != 0 {
		m := snp.Measurements
		if m == nil {
			return ErrNoSevSnpMeasurements
		}
		measure, ok := m[opts.ExpectedLaunchVMSAs]
		if !ok {
			return fmt.Errorf("no golden measurement for %d launch VMSAs", opts.ExpectedLaunchVMSAs)
		}
		if !bytes.Equal(measure, opts.Measurement) {
			return fmt.Errorf("given measure %s does not match measurement for %d VMSAs %s",
				hex.EncodeToString(measure), opts.ExpectedLaunchVMSAs, hex.EncodeToString(opts.Measurement))
		}
	} else if opts.Measurement != nil {
		// Check the measurement against any of the launch VMSA measurements.
		var found bool
		for _, measure := range snp.Measurements {
			if bytes.Equal(measure, opts.Measurement) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("measure %s does not match any golden measurement",
				hex.EncodeToString(opts.Measurement))
		}
	}
	return nil
}

// CheckCertificate returns an error if the given certificate isn't signed by a root of trust, or
// the parsed certificate if its signature is valid.
func CheckCertificate(certder []byte, rootsOfTrust *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if len(certder) == 0 {
		return nil, ErrNoEndorsementCert
	}
	cert, err := x509.ParseCertificate(certder)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: rootsOfTrust, CurrentTime: now}); err != nil {
		return nil, fmt.Errorf("key %v was not signed by a root of trust: %v", cert.Subject, err)
	}
	return cert, nil
}
