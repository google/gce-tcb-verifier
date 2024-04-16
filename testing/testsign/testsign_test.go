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

package testsign

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"golang.org/x/net/context"
	"sync"
	"testing"
	"time"

	"github.com/google/gce-tcb-verifier/sign/memca"
	"github.com/google/gce-tcb-verifier/sign/nonprod"
	sops "github.com/google/gce-tcb-verifier/sign/ops"
	styp "github.com/google/gce-tcb-verifier/sign/types"
	"github.com/google/gce-tcb-verifier/testing/match"
)

const (
	signCommon      = "test-signer"
	signVersionName = "p/t/signer"
)

var (
	now = time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC)
	s   *nonprod.Signer
	ca  *memca.CertificateAuthority
	mu  sync.Once
)

func initTest(t *testing.T) {
	mu.Do(func() {
		ca = memca.Create()
		Init(t, &s, &Options{
			Now:               now,
			CA:                ca,
			Root:              KeyInfo{CommonName: "test-root", KeyVersionName: "p/t/root"},
			PrimarySigningKey: KeyInfo{CommonName: signCommon, KeyVersionName: signVersionName}})()
	})
}

func TestKeysVerify(t *testing.T) {
	initTest(t)
	ctx := context.Background()

	// Cross-check that the signer's public key is the same as the signer cert's public key.
	rsaPub, err := sops.RsaPublicKey(ctx, s, signVersionName)
	if err != nil {
		t.Error(err)
	}
	signerCert, err := sops.CertificateX509(ctx, ca, signVersionName)
	if err != nil {
		t.Error(err)
	}

	if signerCert != nil && !signerCert.PublicKey.(*rsa.PublicKey).Equal(rsaPub) {
		t.Errorf("signerCert.PublicKey is %v, expect %v", signerCert.PublicKey, rsaPub)
	}

	// Make sure the signer's trust chains back to the root.
	if err := sops.VerifyChain(ctx, ca, signVersionName, now); err != nil {
		t.Error(err)
	}
}

func TestSignVerifies(t *testing.T) {
	initTest(t)
	ctx := context.Background()
	message := []byte("This is my test message")

	digest := sha256.Sum256(message)
	signature, err := s.Sign(ctx, signVersionName, styp.Digest{SHA256: digest[:]}, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	signerCert, err := sops.CertificateX509(ctx, ca, signVersionName)
	if err != nil {
		t.Fatal(err)
	}

	if err := sops.VerifySignature(ctx, signerCert, message, signature); err != nil {
		t.Errorf("could not verify signature: %v", err)
	}
}

func TestCertPoorErrors(t *testing.T) {
	m := &MockSigner{
		Certificates: map[string][]byte{},
		CABundles: map[string][]byte{
			signVersionName: []byte{},
			"badPEM": []byte(`
-----BEGIN BAD-----
YmFkCg==
-----END BAD-----
`),
			"badCert": []byte(`-----BEGIN CERTIFICATE-----
YmFkCg==
-----END CERTIFICATE-----
`),
			"extra": []byte(`-----BEGIN CERTIFICATE-----
YmFkCg==
-----END CERTIFICATE-----
extra`),
		},
	}
	tcs := []struct {
		name    string
		key     string
		wantErr string
	}{
		{
			name:    "missing cert",
			key:     signVersionName,
			wantErr: fmt.Sprintf("parse error when decoding CA bundle for %q", signVersionName),
		},
		{
			name:    "missing key",
			key:     "missing",
			wantErr: "missing CA bundle for key \"missing\"",
		},
		{
			name:    "bad pem",
			key:     "badPEM",
			wantErr: "parse error",
		},
		{
			name:    "bad cert",
			key:     "badCert",
			wantErr: "parse error",
		},
		{
			name:    "extra in bundle",
			key:     "extra",
			wantErr: "parse error",
		},
	}
	for _, tc := range tcs {
		if _, err := sops.CertPool(context.Background(), m, tc.key); !match.Error(err, tc.wantErr) {
			t.Errorf("%s: CertPool(_, mockSigner, %q) = %v, want %v", tc.name, tc.key, err, tc.wantErr)
		}
	}
}

func TestCertificateErrors(t *testing.T) {
	m := &MockSigner{
		Certificates: map[string][]byte{
			signVersionName: []byte{},
		},
		CABundles: map[string][]byte{},
	}
	tcs := []struct {
		name    string
		key     string
		wantErr string
	}{
		{
			name:    "missing cert",
			key:     "missing",
			wantErr: "could not fetch certificate for key \"missing\"",
		},
		{
			name:    "bad parse",
			key:     signVersionName,
			wantErr: "could not parse certificate",
		},
	}
	for _, tc := range tcs {
		if _, err := sops.CertificateX509(context.Background(), m, tc.key); !match.Error(err, tc.wantErr) {
			t.Errorf("%s: CertificateX509(_, empty, %q) = %v, want %v", tc.name, tc.key, err, tc.wantErr)
		}
	}
}
