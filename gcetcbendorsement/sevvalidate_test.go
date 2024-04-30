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

package gcetcbendorsement

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"context"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/gce-tcb-verifier/endorse"
	"github.com/google/gce-tcb-verifier/keys"
	"github.com/google/gce-tcb-verifier/sev"
	"github.com/google/gce-tcb-verifier/sign/memca"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/gce-tcb-verifier/testing/nonprod/localnonvcs"
	"github.com/google/gce-tcb-verifier/testing/nonprod/memkm"
	"github.com/google/gce-tcb-verifier/testing/ovmfsev"
	"github.com/google/gce-tcb-verifier/testing/testsign"
	"github.com/google/go-sev-guest/abi"
	cpb "github.com/google/go-sev-guest/proto/check"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	test "github.com/google/go-sev-guest/testing"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestSevValidate(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2024, time.March, 15, 15, 30, 0, 0, time.UTC)
	ctx0 := context.Background()
	ec := &endorse.Context{
		SevSnp: &sev.SnpEndorsementRequest{
			Svn:         2,
			FamilyID:    sev.GCEUefiFamilyID,
			ImageID:     uuid.New().String(),
			LaunchVmsas: 1,
			Product:     spb.SevProduct_SEV_PRODUCT_MILAN,
		},
		ClSpec:    4321,
		Image:     ovmfsev.CleanExample(t, 2*1024*1024),
		VCS:       &localnonvcs.T{Root: dir},
		Timestamp: now,
	}
	manager := memkm.TestOnlyT()
	kc := &keys.Context{
		CA:      memca.TestOnlyCertificateAuthority(),
		Manager: manager,
		Signer:  manager.Signer,
		Random:  testsign.RootRand(),
	}
	ctx1 := keys.NewContext(ctx0, kc)
	ctx2 := endorse.NewContext(ctx1, ec)
	// Create a test endorsement of the clean example firmware.
	if err := endorse.Ovmf(ctx2); err != nil {
		t.Fatalf("endorse.Ovmf() = %v, want nil", err)
	}
	endorsementPath := path.Join(dir, "endorsement.binarypb")
	endorsement, err := os.ReadFile(endorsementPath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) = %v, want nil", endorsementPath, err)
	}
	bundle, err := kc.CA.CABundle(ctx2, "root")
	if err != nil {
		t.Fatalf("kc.CA.CABundle() = %v, want nil", err)
	}
	testroot := x509.NewCertPool()
	if !testroot.AppendCertsFromPEM(bundle) {
		t.Fatalf("testroot.AppendCertsFromPEM(%v) = %v, want nil", bundle, err)
	}

	s, err := test.DefaultTestOnlyCertChain("Milan", now)
	if err != nil {
		t.Fatalf("test.DefaultTestOnlyCertChain() = %v, want nil", err)
	}
	cleanMeasurement := "2247cc90eae3eff72c8d4b4ea5fefb8914bd80ad093859d5d022332eba7c7abe59e13d525c941ede5541191d7149585d"
	meas, _ := hex.DecodeString(cleanMeasurement)
	endorsementURI := fmt.Sprintf("https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/sevsnp/%s.binarypb", cleanMeasurement)
	report := &spb.Report{
		Signature:       []byte("signature"),
		Version:         2,
		GuestSvn:        2,
		ReportData:      make([]byte, abi.ReportSize),
		FamilyId:        make([]byte, abi.FamilyIDSize),
		ImageId:         make([]byte, abi.ImageIDSize),
		Measurement:     meas,
		IdKeyDigest:     make([]byte, abi.IDKeyDigestSize),
		AuthorKeyDigest: make([]byte, abi.AuthorKeyDigestSize),
		HostData:        make([]byte, abi.HostDataSize),
		ReportId:        make([]byte, abi.ReportIDSize),
		ReportIdMa:      make([]byte, abi.ReportIDMASize),
		ChipId:          make([]byte, abi.ChipIDSize),
		Policy:          abi.SnpPolicyToBytes(abi.SnpPolicy{}),
	}
	prodPolicy := abi.SnpPolicyToBytes(abi.SnpPolicy{
		ABIMinor:     0,
		ABIMajor:     0,
		SMT:          true,
		MigrateMA:    true,
		Debug:        false,
		SingleSocket: false,
	})
	tcs := []struct {
		name        string
		attestation *spb.Attestation
		opts        *SevValidateOptions
		wantErr     string
	}{
		{
			name: "Happy path from attestation extra",
			attestation: &spb.Attestation{
				Report: report,
				CertificateChain: &spb.CertificateChain{
					VcekCert: s.Vcek.Raw,
					Extras:   map[string][]byte{sev.GCEFwCertGUID: endorsement}}},
			opts: &SevValidateOptions{
				RootsOfTrust: testroot,
				BasePolicy: &cpb.Policy{
					MinimumVersion: "0.0",
					Policy:         prodPolicy,
				},
			},
		},
		{
			name: "Happy path from bucket",
			attestation: &spb.Attestation{
				Report:           report,
				CertificateChain: &spb.CertificateChain{VcekCert: s.Vcek.Raw}},
			opts: &SevValidateOptions{
				RootsOfTrust: testroot,
				BasePolicy: &cpb.Policy{
					MinimumVersion: "0.0",
					Policy:         prodPolicy,
				},
				Getter: &test.Getter{
					Responses: map[string][]test.GetResponse{endorsementURI: []test.GetResponse{
						test.GetResponse{
							Body: endorsement,
						}}},
				},
			},
		},
		{
			name:        "nil attestation",
			attestation: nil,
			opts:        &SevValidateOptions{},
			wantErr:     "could not extract endorsement",
		},
		{
			name:        "no getter",
			attestation: &spb.Attestation{Report: &spb.Report{Measurement: []byte("blah")}},
			opts:        &SevValidateOptions{Getter: &test.Getter{}},
			wantErr:     "failed to get endorsement",
		},
		{
			name: "bad policy",
			attestation: &spb.Attestation{CertificateChain: &spb.CertificateChain{
				Extras: map[string][]byte{sev.GCEFwCertGUID: endorsement},
			}},
			opts: &SevValidateOptions{BasePolicy: &cpb.Policy{
				Policy:         458752,
				Vmpl:           &wrapperspb.UInt32Value{Value: 4},
				MinimumVersion: "0.0",
			}},
			wantErr: "could not translate policy to validation options",
		},
		{
			name: "bad validate",
			attestation: &spb.Attestation{
				Report: report,
				CertificateChain: &spb.CertificateChain{
					VcekCert: s.Vcek.Raw,
					Extras:   map[string][]byte{sev.GCEFwCertGUID: endorsement},
				}},
			opts: &SevValidateOptions{BasePolicy: &cpb.Policy{
				Policy:         458752,
				Vmpl:           &wrapperspb.UInt32Value{Value: 1},
				MinimumVersion: "0.0",
			}},
			wantErr: "report VMPL 0 is not 1",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if err := SevValidate(ctx0, tc.attestation, tc.opts); !match.Error(err, tc.wantErr) {
				t.Fatalf("SevValidate(_, %v, %v) = %v errored unexpectedly. Want %q", tc.attestation,
					tc.opts, err, tc.wantErr)
			}
		})
	}
}
