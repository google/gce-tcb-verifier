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

// Package testca defines test cases for any implementation of styp.CertificateAuthority.
package testca

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/net/context"
	"testing"

	"github.com/google/gce-tcb-verifier/sign/transform"
	"github.com/google/gce-tcb-verifier/testing/devkeys"

	styp "github.com/google/gce-tcb-verifier/sign/types"
)

func rootCert(t testing.TB) *x509.Certificate {
	t.Helper()
	rootCert, err := transform.PemToCertificate(devkeys.RootCert)
	if err != nil {
		t.Fatalf("transform.PemToCertificate(%q) = %v, want nil", devkeys.RootCert, err)
	}
	return rootCert
}

func signingKeyCert(t testing.TB) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(devkeys.PrimarySigningKeyCert)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(%q) = %v, want nil", devkeys.PrimarySigningKeyCert, err)
	}
	return cert
}

// SetGetRootName tests a CA's PrimaryRootKeyVersion mutation and getter.
func SetGetRootName(ctx context.Context, t testing.TB, ca styp.CertificateAuthority) {
	t.Helper()
	mut := ca.NewMutation()
	want := "rootKey"
	mut.SetPrimaryRootKeyVersion(want)
	if err := ca.Finalize(ctx, mut); err != nil {
		t.Fatalf("ca.Finalize(mut) = %v, want nil", err)
	}

	got, err := ca.PrimaryRootKeyVersion(ctx)
	if err != nil {
		t.Fatalf("ca.PrimaryRootKeyVersion(ctx) = _, %v, want nil", err)
	}
	if got != want {
		t.Errorf("ca.PrimaryRootKeyVersion(ctx) = %v, nil want %v", got, want)
	}
}

// SetGetPrimarySigningKeyName tests a CA's PrimarySingingKeyVersion mutation and getter.
func SetGetPrimarySigningKeyName(ctx context.Context, t testing.TB, ca styp.CertificateAuthority) {
	t.Helper()
	mut := ca.NewMutation()
	want := "primarySigningKey"
	mut.SetPrimarySigningKeyVersion(want)
	if err := ca.Finalize(ctx, mut); err != nil {
		t.Fatalf("ca.Finalize(mut) = %v, want nil", err)
	}

	got, err := ca.PrimarySigningKeyVersion(ctx)
	if err != nil {
		t.Fatalf("ca.PrimarySigningKeyVersion(ctx) = _, %v, want nil", err)
	}
	if got != want {
		t.Errorf("ca.PrimarySigningKeyVersion(ctx) = %v, nil want %v", got, want)
	}
}

// SetGetRootCert tests a CA's SetRootKeyCert mutation and the CABundle getter.
func SetGetRootCert(ctx context.Context, t testing.TB, ca styp.CertificateAuthority) {
	t.Helper()
	want := rootCert(t)
	mut := ca.NewMutation()
	mut.SetRootKeyCert(want)
	if err := ca.Finalize(ctx, mut); err != nil {
		t.Fatalf("ca.Finalize(mut) = %v, want nil", err)
	}

	got, err := ca.CABundle(ctx, "someKey")
	if err != nil {
		t.Fatalf("ca.CABundle(ctx) = _, %v, want nil", err)
	}
	wantPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: want.Raw}))
	if string(got) != wantPEM {
		t.Errorf("ca.CABundle(ctx) = %v, nil want %v", string(got), wantPEM)
	}
}

// AddGetSigningKeyCert tests a CA's AddSigningKeyCert mutation and the Certificate getter.
func AddGetSigningKeyCert(ctx context.Context, t testing.TB, ca styp.CertificateAuthority) {
	t.Helper()
	want := signingKeyCert(t)
	mut := ca.NewMutation()
	mut.AddSigningKeyCert("wootKey", want)
	if err := ca.Finalize(ctx, mut); err != nil {
		t.Fatalf("ca.Finalize(mut) = %v, want nil", err)
	}

	got, err := ca.Certificate(ctx, "wootKey")
	if err != nil {
		t.Fatalf("ca.Certificate(ctx, \"wootKey\") = _, %v, want nil", err)
	}
	if !bytes.Equal(got, want.Raw) {
		t.Errorf("ca.Certificate(ctx, \"wootKey\") = %v, nil want %v", got, want.Raw)
	}
}

// Wipeout tests a CA's Wipeout function after mutating all aspects, such that all primaries are
// cleared, and the added certificates for root and non-root are gone.
func Wipeout(ctx context.Context, t testing.TB, ca styp.CertificateAuthority) {
	t.Helper()
	mut := ca.NewMutation()
	mut.SetRootKeyCert(rootCert(t))
	mut.AddSigningKeyCert("wootKey", signingKeyCert(t))
	mut.SetPrimarySigningKeyVersion("primarySigningKey")
	mut.SetPrimaryRootKeyVersion("rootKey")
	if err := ca.Finalize(ctx, mut); err != nil {
		t.Fatalf("ca.Finalize(mut) = %v, want nil", err)
	}
	if err := ca.Wipeout(ctx); err != nil {
		t.Fatalf("ca.Wipeout(ctx) = %v, want nil", err)
	}
	if got, err := ca.PrimaryRootKeyVersion(ctx); err != nil || got != "" {
		t.Errorf("ca.PrimaryRootKeyVersion(ctx) = %v, %v want %q", got, err, "")
	}
	if got, err := ca.PrimarySigningKeyVersion(ctx); err != nil || got != "" {
		t.Errorf("ca.PrimarySigningKeyVersion(ctx) = %v, %v want %q", got, err, "")
	}
	if got, err := ca.Certificate(ctx, "wootKey"); err == nil {
		t.Errorf("ca.Certificate(ctx, \"wootKey\") = %v, nil want an error", got)
	}
	if got, err := ca.CABundle(ctx, "wootKey"); err == nil {
		t.Errorf("ca.CABundle(ctx, \"wootKey\") = %v, nil want an error", got)
	}
}
