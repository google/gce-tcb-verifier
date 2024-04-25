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

package ops

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/google/gce-tcb-verifier/sign/memca"
	"github.com/google/gce-tcb-verifier/sign/nonprod"
	styp "github.com/google/gce-tcb-verifier/sign/types"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/gce-tcb-verifier/testing/testsign"
)

const rootName = "test-root"
const signingKeyVersionName = "test-signing-key"

var (
	rootmu     sync.Once
	now        time.Time
	signer     *nonprod.Signer
	rootCertMu sync.Once
	rootCert   *x509.Certificate
)

func setRootCert(cert *x509.Certificate) func() {
	return func() {
		rootCert = cert
	}
}

func initroot(t *testing.T) func() {
	return func() {
		now = time.Now()
		s, err := testsign.MakeSigner(context.Background(), &testsign.Options{
			CA:                memca.Create(),
			Now:               now,
			Root:              testsign.KeyInfo{CommonName: styp.RootCommonName, KeyVersionName: rootName},
			PrimarySigningKey: testsign.KeyInfo{CommonName: styp.UEFISigningCommonName, KeyVersionName: signingKeyVersionName}})
		if err != nil {
			t.Fatal(err)
		}
		signer = s
	}
}

func createRootCert(t *testing.T) func() {
	return func() {
		rootmu.Do(initroot(t))
		cert, err := GoogleCertificate(context.Background(), &GoogleCertRequest{
			Template: &GoogleCertTemplate{
				Serial:            big.NewInt(1),
				PublicKey:         &signer.Keys[rootName].PublicKey,
				SubjectCommonName: styp.RootCommonName,
				NotBefore:         now,
			},
			IssuerKeyVersionName: rootName,
			Random:               testsign.RootRand(),
			Signer:               signer,
		})
		if err != nil {
			panic(err)
		}
		rootCert = cert
	}
}

type badSigner struct{}

func (s *badSigner) PublicKey(context.Context, string) ([]byte, error) {
	return nil, nil
}

func (s *badSigner) Sign(context.Context, string, styp.Digest, crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("badSigner.Signer: unimplemented")
}

func TestCreateCertificateRoot(t *testing.T) {
	rootmu.Do(initroot(t))

	badSign0, err := testsign.MakeSigner(context.Background(), &testsign.Options{
		Now:               now,
		CA:                memca.Create(),
		Root:              testsign.KeyInfo{CommonName: styp.RootCommonName, KeyVersionName: "wrong-root"},
		PrimarySigningKey: testsign.KeyInfo{CommonName: styp.UEFISigningCommonName, KeyVersionName: "ignore"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		commonName string
		signer     styp.Signer
		wantErr    string
	}{
		{
			name:       "happy path",
			commonName: styp.RootCommonName,
			signer:     signer,
		},
		{
			name:       "happy path different common name",
			commonName: "uncommon",
			signer:     signer,
		},
		{
			name:    "wrong key",
			signer:  badSign0,
			wantErr: "could not create certificate",
		},
		{
			name:    "no public key",
			signer:  &badSigner{},
			wantErr: "could not create certificate",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GoogleCertificate(context.Background(), &GoogleCertRequest{
				Template: &GoogleCertTemplate{
					Serial:            big.NewInt(1),
					PublicKey:         &signer.Keys[rootName].PublicKey,
					SubjectCommonName: tc.commonName,
					NotBefore:         now,
				},
				IssuerKeyVersionName: rootName,
				Random:               testsign.RootRand(),
				Signer:               tc.signer,
			})
			if !match.Error(err, tc.wantErr) {
				t.Fatalf("GoogleCertificate(...) = %v want %q", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if err := got.CheckSignatureFrom(got); err != nil {
				t.Errorf("self.CheckSignatureFrom(%v) = %v, want nil", got, err)
			}
			if got.Subject.CommonName != tc.commonName || got.Issuer.CommonName != tc.commonName {
				t.Errorf("Got root certificate common names %q %q, want %q", got.Subject.CommonName,
					got.Issuer.CommonName, tc.commonName)
			}
			rootCertMu.Do(setRootCert(got))
		})
	}
}

func TestCreateCertificateSigningKey(t *testing.T) {
	rootCertMu.Do(createRootCert(t)) // Make the root cert if we haven't already.

	tests := []struct {
		name       string
		commonName string
	}{
		{
			name:       "usual name",
			commonName: styp.UEFISigningCommonName,
		},
		{
			name:       "unusual name",
			commonName: "uncommon",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GoogleCertificate(context.Background(), &GoogleCertRequest{
				Template: &GoogleCertTemplate{
					Serial:            big.NewInt(2),
					PublicKey:         &signer.Keys[signingKeyVersionName].PublicKey,
					SubjectCommonName: tc.commonName,
					NotBefore:         now,
					Issuer:            rootCert,
				},
				IssuerKeyVersionName: rootName,
				Random:               testsign.SignerRand(),
				Signer:               signer,
			})
			if err != nil {
				t.Fatalf("GoogleCertificate(...) = %v. Want nil", err)
			}
			if err := got.CheckSignatureFrom(rootCert); err != nil {
				t.Errorf("%v.CheckSignatureFrom(rootCert) = %v. Want nil", got, err)
			}
			if got.Subject.CommonName != tc.commonName {
				t.Errorf("Got signing key certificate common name %q, want %q",
					got.Subject.CommonName, tc.commonName)
			}
			if got.Issuer.CommonName != styp.RootCommonName {
				t.Errorf("Got signing key certificate issuer common name %q, want %q",
					got.Issuer.CommonName, styp.RootCommonName)
			}
		})
	}
}
