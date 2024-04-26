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
	"context"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/rand" // Unsafe randomness source only for testing.
	"testing"
	"time"

	"github.com/google/gce-tcb-verifier/sign/nonprod"
	styp "github.com/google/gce-tcb-verifier/sign/types"
)

func sameRand(source int64) io.Reader {
	return rand.New(rand.NewSource(source))
}

// RootRand is a test-only deterministic source of randomness for use with the root key.
func RootRand() io.Reader { return sameRand(42) }

// SignerRand is a test-only deterministic source of randomness for use with the signer key.
func SignerRand() io.Reader { return sameRand(999) }

func pkixName(commonName string, serialNumber int64) pkix.Name {
	return pkix.Name{
		Country:            []string{"Republic of Test"},
		Organization:       []string{"Test Inc."},
		OrganizationalUnit: []string{"Test division"},
		Province:           []string{"New Test"},
		SerialNumber:       fmt.Sprintf("%d", serialNumber),
		CommonName:         commonName,
	}
}

// KeyInfo represents configurable parts of a fake signer's representation of a key.
type KeyInfo struct {
	// CommonName is the key's certificate subject common name.
	CommonName string
	// KeyVersionName is the key's unique name (path) for use in signing requests.
	KeyVersionName string
}

// Nonprod returns the nonprod signer's key representation from test-only key metadata.
func (k KeyInfo) Nonprod(serialNumber int64) nonprod.Key {
	name := pkixName(k.CommonName, serialNumber)
	return nonprod.Key{
		Info: nonprod.KeyInfo{
			PkixName:       &name,
			KeyVersionName: k.KeyVersionName,
		},
	}
}

// Options carries all the configurable components for a non-production in-memory signer.
type Options struct {
	Now               time.Time
	Random            io.Reader
	CA                styp.CertificateAuthority
	Root              KeyInfo
	PrimarySigningKey KeyInfo
	SigningKeys       []KeyInfo
}

// MakeSigner creates a new Signer with signer keys of the given names.
func MakeSigner(_ context.Context, opts *Options) (*nonprod.Signer, error) {
	randomSource := rand.NewSource(12345)
	random := rand.New(randomSource)
	serialNumber := int64(1)
	fakeRoot := opts.Root.Nonprod(serialNumber)
	fakeSigners := make([]nonprod.Key, len(opts.SigningKeys)+1)
	for i, signingKey := range append([]KeyInfo{opts.PrimarySigningKey}, opts.SigningKeys...) {
		serialNumber++
		fakeSigners[i] = signingKey.Nonprod(serialNumber)
	}

	return nonprod.MakeCustomSigner(context.Background(), &nonprod.Options{
		Now:               opts.Now,
		CA:                opts.CA,
		Random:            random,
		Root:              fakeRoot,
		PrimarySigningKey: fakeSigners[0],
		SigningKeys:       fakeSigners[1:],
	})
}

// Init returns a thunk that sets the given signer pointer to a testsign.Signer.
func Init(t testing.TB, s **nonprod.Signer, opts *Options) func() {
	return func() {
		t.Helper() // A function that can fail `t` other than the test method should get this called.
		signer, err := MakeSigner(context.Background(), opts)
		if err != nil {
			t.Fatal(err)
		}
		*s = signer
	}
}
