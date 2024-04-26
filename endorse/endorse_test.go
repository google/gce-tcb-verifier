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

package endorse

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/gce-tcb-verifier/keys"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/gce-tcb-verifier/sev"
	"github.com/google/gce-tcb-verifier/sign/memca"
	"github.com/google/gce-tcb-verifier/sign/nonprod"
	sops "github.com/google/gce-tcb-verifier/sign/ops"
	"github.com/google/gce-tcb-verifier/testing/testsign"
	"github.com/google/gce-tcb-verifier/timeproto"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

const signKey = "test-signer"

var (
	now = time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC)
	s   *nonprod.Signer
	ca  *memca.CertificateAuthority
	mu  sync.Once
)

func initTest(t testing.TB) {
	mu.Do(func() {
		ca = memca.Create()
		testsign.Init(t, &s, &testsign.Options{Now: now,
			CA:                ca,
			Root:              testsign.KeyInfo{CommonName: "meh", KeyVersionName: "test-root"},
			PrimarySigningKey: testsign.KeyInfo{CommonName: "dkdc", KeyVersionName: signKey}})()
	})
}

func TestSignDoc(t *testing.T) {
	initTest(t)
	ctx0 := context.Background()
	bundle, err := ca.CABundle(ctx0, signKey)
	if err != nil {
		t.Fatal(err)
	}
	familyUUID := uuid.MustParse(sev.GCEUefiFamilyID)
	imageUUID := uuid.MustParse("87654321-dead-beef-c0de-123456789ABC")
	doc := &epb.VMGoldenMeasurement{
		Timestamp: timeproto.To(now),
		ClSpec:    123456789,
		CaBundle:  bundle,
		SevSnp: &epb.VMSevSnp{
			Svn:      0x1337,
			FamilyId: familyUUID[:],
			ImageId:  imageUUID[:],
			Policy:   0x70000,
			Measurements: map[uint32][]byte{4: {
				0x1a, 0x8c, 0xd8, 0x03, 0x9c, 0xdc, 0xdc, 0xd1, 0xec, 0x98, 0x00, 0xca, 0x21, 0x5b, 0xa5, 0xcb,
				0xbe, 0xd4, 0x37, 0x69, 0x7d, 0xeb, 0xf0, 0xb2, 0xfc, 0x1a, 0x9b, 0x87, 0x3f, 0x1e, 0xb1, 0x5f,
				0x82, 0xdc, 0x7d, 0x5c, 0xf2, 0x46, 0xdb, 0xee, 0x4d, 0xf1, 0xbb, 0x9d, 0x3b, 0x6c, 0x7a, 0x16}},
		},
	}
	ca.PrimarySigningKey = signKey
	ctx1 := keys.NewContext(ctx0, &keys.Context{
		Signer: s,
		CA:     ca,
	})
	ctx := NewContext(ctx1, &Context{
		Timestamp: now,
	})
	endorsement, err := SignDoc(ctx, doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := sops.VerifySignatureFromCA(ctx, ca, signKey, now,
		endorsement.SerializedUefiGolden, endorsement.GetSignature()); err != nil {
		t.Error(err)
	}
	backagain := &epb.VMGoldenMeasurement{}
	if err := proto.Unmarshal(endorsement.SerializedUefiGolden, backagain); err != nil {
		t.Fatal("SignDoc() returned a document whose serialized golden measurement does not deserialize")
	}
	if !cmp.Equal(backagain, doc, cmp.Comparer(proto.Equal)) {
		t.Errorf("SignDoc's serialized golden %v is not %v", backagain, doc)
	}
}

func TestBadRequest(t *testing.T) {
	tests := []struct {
		name    string
		input   *Context
		wantErr string
	}{
		{
			name: "No technology",
			input: &Context{
				ClSpec:    123456789,
				Timestamp: now,
			},
			wantErr: "no supported technology specified in signing request",
		},
		{
			name: "bad familyid",
			input: &Context{
				ClSpec: 123456789,
				SevSnp: &sev.SnpEndorsementRequest{
					Svn:      0x1337,
					FamilyID: "not a guid",
				},
				Timestamp: now,
			},
			wantErr: "could not parse family_id",
		},
		{
			name: "bad imageid",
			input: &Context{
				ClSpec: 123456789,
				SevSnp: &sev.SnpEndorsementRequest{
					Svn:      0x1337,
					FamilyID: sev.GCEUefiFamilyID,
					ImageID:  "not a guid",
				},
				Timestamp: now,
			},
			wantErr: "could not parse image_id",
		},
	}
	for _, tc := range tests {
		_, err := GoldenMeasurement(NewContext(context.Background(), tc.input))
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: SignDoc() = %v, want %s", tc.name, err, tc.wantErr)
		}
	}
}
