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

package testkms

import (
	"context"
	"testing"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/google/gce-tcb-verifier/keys"
	"github.com/google/gce-tcb-verifier/keys/gcpkms"
	"github.com/google/gce-tcb-verifier/rotate"
	"github.com/google/gce-tcb-verifier/sign/gcsca"
	"github.com/google/gce-tcb-verifier/sign/nonprod"
	"github.com/google/gce-tcb-verifier/storage/local"
	"github.com/google/gce-tcb-verifier/testing/testkm"
	"github.com/google/gce-tcb-verifier/testing/testsign"
)

func TestParseResource(t *testing.T) {
	// Interpret want == "" as expecting a parsing error.
	tcs := []struct {
		good string
		bad  string
	}{
		{good: "projects/b/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"},
		{good: "projects/b/locations/l/keyRings/r/cryptoKeys/k"},
		{good: "projects/b/locations/l/keyRings/r"},
		{bad: "projects/b/locations/l/keyRings/r/cryptoKeys/k/versions/1"},
		{bad: "projects/b/locations/l/keyRings/r/keys/k"},
		{bad: "proj/b/locations/l/keyRings/r"},
		{bad: "projects/b/locs/l/keyRings/r"},
		{bad: "projects/b/locations/l/rings/r"},
		{bad: "projects/b/locations/l/cryptoKeys/k/cryptoKeyVersions"},
		{bad: "projects/b/locations/l/keyRings/r/cryptoKeys//cryptoKeyVersions/1"},
		{bad: "projects/b/locations/l/keyRings/r/cryptoKeys//cryptoKeyVersions/"},
		{bad: "projects/b/locations/l/keyRings//cryptoKeys/k/cryptoKeyVersions/"},
		{bad: "projects/b/locations//keyRings/r/cryptoKeys//cryptoKeyVersions/"},
		{bad: "projects//locations/l/keyRings/r/cryptoKeys//cryptoKeyVersions/"},
	}
	for _, tc := range tcs {
		if tc.good == "" {
			got := parseResource(tc.bad)
			if got != nil {
				t.Errorf("parseResource(%q) = %v, want nil", tc.bad, parseResource(tc.bad))
			}
		} else {
			got := parseResource(tc.good)
			if got == nil || got.String() != tc.good {
				t.Errorf("parseResource(%q) = %v, want %q", tc.good, got, tc.good)
			}
		}
	}
}

func TestFakeKms(t *testing.T) {
	signer := &nonprod.Signer{Rand: testsign.RootRand()}
	kmsServer := &FakeKmsServer{Signer: signer}
	iamServer := &IAMPolicyServer{}
	conn := InitGrpcKmsTestServers(t, kmsServer, iamServer)
	m := &gcpkms.Manager{
		Project:   "proj",
		Location:  "loc",
		KeyRingID: "test-ring",
		KeyClient: kmspb.NewKeyManagementServiceClient(conn),
		IAMClient: iampb.NewIAMPolicyClient(conn),
	}
	ctx0 := context.Background()
	ctx1 := keys.NewContext(ctx0, &keys.Context{
		Random: testsign.RootRand(),
		Signer: signer,
		CA: &gcsca.CertificateAuthority{
			RootPath:            "root.crt",
			PrivateBucket:       "private-bucket",
			SigningCertDirInGCS: "testcerts",
			Storage:             &local.StorageClient{Root: t.TempDir()},
		},
		Manager: m,
	})
	bctx := gcpkms.NewBootstrapContext(ctx1, &gcpkms.BootstrapContext{
		RootKeyID:           "test-root-key",
		SigningKeyID:        "test-signing-key",
		SigningKeyOperators: []string{"example@example.com"},
	})
	testkm.Bootstrap(bctx, t)
	rctx := gcpkms.NewSigningKeyContext(ctx1, &gcpkms.SigningKeyContext{
		SigningKeyID: "test-signing-key",
	})
	rotatedKeyVersionName := m.FullKeyName("test-signing-key") + "/cryptoKeyVersions/2"
	testkm.Rotate(rctx, t, rotatedKeyVersionName)
	if err := rotate.Wipeout(ctx1); err != nil {
		t.Errorf("rotate.Wipeout() = %v, want nil", err)
	}
	testkm.PostWipeoutProperties(ctx1, t, &testkm.Options{
		RootKeyVersionName:           m.FullKeyName("test-root-key") + "/cryptoKeyVersions/1",
		PrimarySigningKeyVersionName: rotatedKeyVersionName,
	})
}
