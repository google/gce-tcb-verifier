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

package certs

import (
	"golang.org/x/net/context"
	"testing"
	"time"

	"github.com/google/gce-tcb-verifier/rotate"
	"github.com/google/gce-tcb-verifier/sign/memca"
	"github.com/google/gce-tcb-verifier/testing/testsign"
)

func TestTemplateFromCertBootstrapRoot(t *testing.T) {
	ctx0 := context.Background()
	now := time.Date(2023, time.February, 21, 4, 28, 0, 0, time.UTC)
	ctx := rotate.NewBootstrapContext(ctx0, &rotate.BootstrapContext{
		Now:               now,
		RootKeyCommonName: "Rudte",
	})
	templateTime := time.Date(2023, time.February, 11, 1, 8, 0, 0, time.UTC)
	ca := memca.Create()
	signer, err := testsign.MakeSigner(ctx, &testsign.Options{
		Now:               templateTime,
		CA:                ca,
		Root:              testsign.KeyInfo{KeyVersionName: "root", CommonName: "root"},
		PrimarySigningKey: testsign.KeyInfo{KeyVersionName: "ignored", CommonName: "ignored"},
	})
	key := signer.Keys[ca.PrimarySigningKey]
	rootCert := ca.Certs[ca.RootName]
	if err != nil {
		t.Fatal(err)
	}
	pubKey := key.Public()
	got, err := TemplateFromCert(ctx, rootCert, pubKey)
	if err != nil {
		t.Fatalf("TemplateFromCert(_, %v, _) = %v, %v. Want cert, nil", rootCert, got, err)
	}
	if got.PublicKey != pubKey {
		t.Errorf("TemplateFromCert(_, %v, _) = %v, nil. Want public key %v", rootCert, got, pubKey)
	}
	if got.Subject.CommonName != "Rudte" {
		t.Errorf("TemplateFromCert(_, %v, _) = %v, nil. Want subject common name \"Rudte\"", rootCert, got)
	}
	if got.Issuer.CommonName != "Rudte" {
		t.Errorf("TemplateFromCert(_, %v, _) = %v, nil. Want issuer common name \"Rudte\"", rootCert, got)
	}
	if !got.IsCA {
		t.Errorf("TemplateFromCert(_, %v, _) = %v, nil. Want IsCA", rootCert, got)
	}
}

func TestTemplateFromCertBootstrapSigner(t *testing.T) {
	ctx0 := context.Background()
	now := time.Date(2023, time.February, 21, 4, 28, 0, 0, time.UTC)
	ctx := rotate.NewBootstrapContext(ctx0, &rotate.BootstrapContext{
		Now:                  now,
		SigningKeyCommonName: "tangent",
	})
	templateTime := time.Date(2023, time.February, 11, 1, 8, 0, 0, time.UTC)
	ca := memca.Create()
	signer, err := testsign.MakeSigner(ctx, &testsign.Options{
		Now:               templateTime,
		CA:                ca,
		Root:              testsign.KeyInfo{KeyVersionName: "ignored", CommonName: "theroot"},
		PrimarySigningKey: testsign.KeyInfo{KeyVersionName: "sign", CommonName: "siner"},
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := signer.GenerateSigningKey("thetest")
	if err != nil {
		t.Fatal(err)
	}
	signerCert := ca.Certs[ca.PrimarySigningKey]
	if err != nil {
		t.Fatal(err)
	}
	pubKey := key.Public()
	got, err := TemplateFromCert(ctx, signerCert, pubKey)
	if err != nil {
		t.Fatalf("TemplateFromCert(_, %v, _) = %v, %v. Want cert, nil", signerCert, got, err)
	}
	if got.PublicKey != pubKey {
		t.Errorf("TemplateFromCert(_, %v, _) = %v, nil. Want public key %v", signerCert, got, pubKey)
	}
	if got.Subject.CommonName != "tangent" {
		t.Errorf("TemplateFromCert(_, %v, _) = %v, nil. Want subject common name \"tangent\"", signerCert, got)
	}
	if got.Issuer.CommonName != "theroot" {
		t.Errorf("TemplateFromCert(_, %v, _) = %v, nil. Want issuer common name \"theroot\"", signerCert, got)
	}
	if got.IsCA {
		t.Errorf("TemplateFromCert(_, %v, _) = %v, nil. Want !IsCA", signerCert, got)
	}
}

func TestTemplateFromCertSigningKey(t *testing.T) {
	ctx0 := context.Background()
	now := time.Date(2023, time.February, 21, 4, 28, 0, 0, time.UTC)
	ctx := rotate.NewSigningKeyContext(ctx0, &rotate.SigningKeyContext{
		Now:                  now,
		SigningKeyCommonName: "sine",
	})
	templateTime := time.Date(2023, time.February, 11, 1, 8, 0, 0, time.UTC)
	ca := memca.Create()
	signer, err := testsign.MakeSigner(ctx, &testsign.Options{
		Now:               templateTime,
		CA:                ca,
		Root:              testsign.KeyInfo{KeyVersionName: "blop", CommonName: "blorp"},
		PrimarySigningKey: testsign.KeyInfo{KeyVersionName: "signer", CommonName: "signer"},
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := signer.GenerateSigningKey("third")
	if err != nil {
		t.Fatal(err)
	}
	signerCert := ca.Certs[ca.PrimarySigningKey]
	if err != nil {
		t.Fatal(err)
	}
	pubKey := key.Public()
	got, err := TemplateFromCert(ctx, signerCert, pubKey)
	if err != nil {
		t.Fatalf("TemplateFromCert(_, %v, _) = %v, %v. Want cert, nil", signerCert, got, err)
	}
	if got.PublicKey != pubKey {
		t.Errorf("TemplateFromCert(_, %v, _) = %v, nil. Want public key %v", signerCert, got, pubKey)
	}
	if got.Subject.CommonName != "sine" {
		t.Errorf("TemplateFromCert(_, %v, _) = %v, nil. Want subject common name \"sine\"", signerCert, got)
	}
	if got.Issuer.CommonName != "blorp" {
		t.Errorf("TemplateFromCert(_, %v, _) = %v, nil. Want issuer common name \"blorp\"", signerCert, got)
	}
	if got.IsCA {
		t.Errorf("TemplateFromCert(_, %v, _) = %v, nil. Want !IsCA", signerCert, got)
	}
}
