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

package verify

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"golang.org/x/net/context"
	"math/rand" // insecure rand for test only.
	"sync"
	"testing"
	"time"

	"github.com/google/gce-tcb-verifier/endorse"
	"github.com/google/gce-tcb-verifier/keys"
	oabi "github.com/google/gce-tcb-verifier/ovmf/abi"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	rpb "github.com/google/gce-tcb-verifier/proto/releases"
	"github.com/google/gce-tcb-verifier/sev"
	"github.com/google/gce-tcb-verifier/sign/memca"
	"github.com/google/gce-tcb-verifier/sign/nonprod"
	"github.com/google/gce-tcb-verifier/sign/ops"
	styp "github.com/google/gce-tcb-verifier/sign/types"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/gce-tcb-verifier/testing/ovmfsev"
	"github.com/google/gce-tcb-verifier/timeproto"
	"github.com/google/gce-tcb-verifier/verify/verifytest"
	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	stest "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify/testdata"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

var (
	testSigner     *nonprod.Signer
	testCA         *memca.CertificateAuthority
	initSignerOnce sync.Once
	now            time.Time
	rot            *x509.CertPool
)

var wrote = make(map[string][]byte)

type endorseArgs struct {
	signatureDir string
	uefiDir      string
	firmwares    []string
	uefis        [][]byte
	expectedMap  *rpb.VMEndorsementMap
}

const (
	_KB = 1024
	_MB = 1024 * _KB
)

func initSigner(t *testing.T) func() {
	return func() {
		results := verifytest.Data(t)
		testSigner = results.TestSigner
		testCA = results.TestCA
		now = results.Now
		rot = results.Rot
	}
}

func TestVerify(t *testing.T) {
	initSignerOnce.Do(initSigner(t))
	ctx0 := context.Background()
	bundle, err := testCA.CABundle(ctx0, verifytest.SignKey)
	if err != nil {
		t.Fatal(err)
	}
	uefi := make([]byte, 2*_MB)
	rnd := rand.New(rand.NewSource(6502))
	if _, err := rnd.Read(uefi); err != nil {
		t.Fatalf("could not populate uefi: %v", err)
	}
	if err := ovmfsev.InitializeSevGUIDTable(uefi[:], oabi.FwGUIDTableEndOffset, ovmfsev.SevEsAddrVal, ovmfsev.DefaultSnpSections()); err != nil {
		t.Fatalf("ovmfsev.InitializeSevGUIDTable() errored unexpectedly: %v", err)
	}

	uefidigest := sha512.Sum384(uefi)
	fakeMeasurement := []byte{
		0x1a, 0x8c, 0xd8, 0x03, 0x9c, 0xdc, 0xdc, 0xd1, 0xec, 0x98, 0x00, 0xca, 0x21, 0x5b, 0xa5, 0xcb,
		0xbe, 0xd4, 0x37, 0x69, 0x7d, 0xeb, 0xf0, 0xb2, 0xfc, 0x1a, 0x9b, 0x87, 0x3f, 0x1e, 0xb1, 0x5f,
		0x82, 0xdc, 0x7d, 0x5c, 0xf2, 0x46, 0xdb, 0xee, 0x4d, 0xf1, 0xbb, 0x9d, 0x3b, 0x6c, 0x7a, 0x16}
	imageUUIDstring := "87654321-dead-beef-c0de-123456789ABC"
	familyUUID := uuid.MustParse(sev.GCEUefiFamilyID)
	imageUUID := uuid.MustParse(imageUUIDstring)
	doc := &epb.VMGoldenMeasurement{
		Timestamp: timeproto.To(now),
		ClSpec:    123456789,
		CaBundle:  bundle,
		Digest:    uefidigest[:],
		SevSnp: &epb.VMSevSnp{
			Svn:          0x1337,
			FamilyId:     familyUUID[:],
			ImageId:      imageUUID[:],
			Policy:       0x70000,
			Measurements: map[uint32][]byte{4: fakeMeasurement},
		},
	}

	// Get the serialization before SignDoc sets the Cert field.
	docBytes, err := proto.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	ctx1 := keys.NewContext(ctx0, &keys.Context{Signer: testSigner, CA: testCA})
	ctx := endorse.NewContext(ctx1, &endorse.Context{
		SevSnp: &sev.SnpEndorsementRequest{
			Svn:         doc.SevSnp.Svn,
			FamilyID:    sev.GCEUefiFamilyID,
			ImageID:     imageUUIDstring,
			LaunchVmsas: 4,
			Product:     spb.SevProduct_SEV_PRODUCT_MILAN,
		},
		Image:         uefi,
		ClSpec:        doc.ClSpec,
		Commit:        doc.Commit,
		CandidateName: "noh",
		ReleaseBranch: "nuh",
		Timestamp:     now,
	})
	endorsement, err := endorse.SignDoc(ctx, doc)
	if err != nil {
		t.Fatal(err)
	}

	scratchDoc, err := endorse.GoldenMeasurement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if scratchDoc.SevSnp == nil {
		scratchDoc.SevSnp = &epb.VMSevSnp{}
	}
	scratchDoc.SevSnp.Measurements = map[uint32][]byte{4: fakeMeasurement}
	scratchEndorsement, err := endorse.SignDoc(ctx, scratchDoc)
	if err != nil {
		t.Fatal(err)
	}

	// SignDoc automatically sets the Cert field, so sign the bytes directly.
	digest := sha256.Sum256(docBytes)
	signature, err := testSigner.Sign(ctx, testCA.PrimarySigningKey, styp.Digest{
		SHA256: digest[:],
	}, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("could not sign golden measurement: %v", err)
	}
	badEndorsement := &epb.VMLaunchEndorsement{
		SerializedUefiGolden: docBytes,
		Signature:            signature,
	}

	pool, err := ops.CertPool(ctx, testCA, verifytest.SignKey)
	if err != nil {
		t.Fatal(err)
	}
	badpool := x509.NewCertPool()
	badpool.AddCert(testCA.Certs["unused-key"])

	tcs := []struct {
		name        string
		pool        *x509.CertPool
		endorsement *epb.VMLaunchEndorsement
		snp         *SNPOptions
		wantErr     string
	}{
		{
			name:        "happy path",
			endorsement: endorsement,
			pool:        pool,
			snp:         &SNPOptions{},
		},
		{
			name:        "e2e happy path",
			endorsement: scratchEndorsement,
			pool:        pool,
			snp:         &SNPOptions{},
		},
		{
			name:        "happy snp measurement [any VMSA]",
			endorsement: endorsement,
			pool:        pool,
			snp:         &SNPOptions{measurement: fakeMeasurement},
		},
		{
			name:        "happy snp measurement [4 VMSAs]",
			endorsement: endorsement,
			pool:        pool,
			snp:         &SNPOptions{measurement: fakeMeasurement, ExpectedLaunchVMSAs: 4},
		},
		{
			name:        "snp measurement wrong VMSAs",
			endorsement: endorsement,
			pool:        pool,
			snp:         &SNPOptions{measurement: fakeMeasurement, ExpectedLaunchVMSAs: 8},
			wantErr:     "no golden measurement for 8 launch VMSAs",
		},
		{
			name:        "bad pool",
			endorsement: endorsement,
			pool:        badpool,
			snp:         &SNPOptions{},
			wantErr:     "was not signed by a root of trust",
		},
		{
			name:        "no cert",
			endorsement: badEndorsement,
			pool:        pool,
			snp:         &SNPOptions{},
			wantErr:     ErrNoEndorsementCert.Error(),
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			digest := sha512.Sum384(uefi)
			if err := EndorsementProto(tc.endorsement, &Options{
				SNP:                tc.snp,
				RootsOfTrust:       tc.pool,
				ExpectedUefiSha384: digest[:],
			}); !match.Error(err, tc.wantErr) {
				t.Fatalf("Endorsement(_, _, {pool: _, ...}) = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestSNPValidateFunc(t *testing.T) {
	tests := []struct {
		name    string
		opt     *validate.CertEntryOption
		wantErr string
	}{
		{
			name: "missing okay",
			opt: &validate.CertEntryOption{
				Kind:     validate.CertEntryAllowMissing,
				Validate: SNPValidateFunc(&Options{SNP: &SNPOptions{}}),
			},
			wantErr: "",
		},
		{
			name: "missing and required, no getter",
			opt: &validate.CertEntryOption{
				Kind:     validate.CertEntryRequire,
				Validate: SNPValidateFunc(&Options{SNP: &SNPOptions{}}),
			},
			wantErr: "endorsement getter is nil",
		},
		{
			name: "missing and required, getter error",
			opt: &validate.CertEntryOption{
				Kind: validate.CertEntryRequire,
				Validate: SNPValidateFunc(&Options{SNP: &SNPOptions{}, Getter: &stest.Getter{
					Responses: map[string][]stest.GetResponse{
						"https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/sevsnp/2247cc90eae3eff72c8d4b4ea5fefb8914bd80ad093859d5d022332eba7c7abe59e13d525c941ede5541191d7149585d.binarypb": []stest.GetResponse{
							{Error: fmt.Errorf("nope to that")},
						},
					},
				}}),
			},
			wantErr: "nope to that",
		},
		{
			name: "required, getter success",
			opt: &validate.CertEntryOption{
				Kind: validate.CertEntryRequire,
				Validate: SNPValidateFunc(&Options{
					SNP:          &SNPOptions{},
					RootsOfTrust: rot,
					Getter: &stest.Getter{
						Responses: map[string][]stest.GetResponse{
							"https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/sevsnp/2247cc90eae3eff72c8d4b4ea5fefb8914bd80ad093859d5d022332eba7c7abe59e13d525c941ede5541191d7149585d.binarypb": []stest.GetResponse{
								{Body: verifytest.FakeEndorsement(t)},
							},
						},
					}}),
			},
		},
	}

	tcs := stest.TestCases()
	attestation := &spb.Attestation{
		Report: &spb.Report{},
		CertificateChain: &spb.CertificateChain{
			VcekCert: testdata.VcekBytes,
		}}
	if err := prototext.Unmarshal([]byte(tcs[0].OutputProto), attestation.GetReport()); err != nil {
		t.Fatal(err)
	}

	attestation.Report.Measurement = make([]byte, abi.MeasurementSize)
	meas, err := hex.DecodeString(verifytest.CleanExampleMeasurement)
	if err != nil {
		t.Fatal(err)
	}
	attestation.Report.Measurement = meas
	attestation.Report.ReportedTcb = 0x4405000000000002
	attestation.Report.CurrentTcb = 0x4405000000000002
	attestation.Report.CommittedTcb = 0x4405000000000002

	for _, tc := range tests {
		if err := validate.SnpAttestation(attestation, &validate.Options{
			GuestPolicy: abi.SnpPolicy{Debug: true},
			CertTableOptions: map[string]*validate.CertEntryOption{
				sev.GCEFwCertGUID: tc.opt,
			}}); !match.Error(err, tc.wantErr) {
			t.Errorf("validate.SnpAttestation(...SNPValidateFunc(%v)...) = %v, want %q", tc.opt, err, tc.wantErr)
		}
	}
}
