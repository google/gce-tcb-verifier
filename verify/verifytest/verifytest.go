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

// Package verifytest provides testonly data for verifying UEFI endorsements.
package verifytest

import (
	"context"
	"crypto/x509"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/gce-tcb-verifier/cmd"
	"github.com/google/gce-tcb-verifier/sign/memca"
	"github.com/google/gce-tcb-verifier/sign/nonprod"
	"github.com/google/gce-tcb-verifier/testing/devkeys"
	"github.com/google/gce-tcb-verifier/testing/fakeovmf"
	"github.com/google/gce-tcb-verifier/testing/nonprod/localnonvcs"
	"github.com/google/gce-tcb-verifier/testing/nonprod/memkm"
	"github.com/google/gce-tcb-verifier/testing/testsign"
)

const (
	// SignKey is the key version name for the UEFI signer.
	SignKey = "projects/testProject/locations/us-west1/keyRings/gce-cc-ring/cryptoKeys/gce-uefi-signer/cryptoKeyVersions/1"
	// CleanExampleMeasurement is the hex encoding of a 2MiB 1 VMSA measurement of the CleanExample
	// firmware binary.
	CleanExampleMeasurement = "20ec0dbd1c0a26d184a6f11ec5a796d68ec03c9d101bdd84c03f3d9cbbc4a292a9fad098edacfa04da0da58f20be885e"
	// CleanTdxExampleMeasurement is the hex encoding of a 2MiB c3-standard-4 measurement of the CleanExample.
	CleanTdxExampleMeasurement = "0d126d4468fba7200f214da27e6a729846cb2fe6ab084a2c15bb39ac85d193ed7f050525a1cd96052d0597362356c9ac"
	// CleanExampleURL is the URL of the endorsement of the CleanExample firmware binary.
	CleanExampleURL = "https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/sevsnp/20ec0dbd1c0a26d184a6f11ec5a796d68ec03c9d101bdd84c03f3d9cbbc4a292a9fad098edacfa04da0da58f20be885e.binarypb"
)

// FakeData encapsulates resources needed for testing UEFI endorsement verification.
type FakeData struct {
	TestSigner *nonprod.Signer
	TestCA     *memca.CertificateAuthority
	Now        time.Time
	Rot        *x509.CertPool
}

// Data returns fake data for testing UEFI signatures.
func Data(t testing.TB) *FakeData {
	result := &FakeData{
		TestCA: memca.Create(),
		Rot:    x509.NewCertPool(),
		Now:    time.Now(),
	}
	s, err := testsign.MakeSigner(context.Background(), &testsign.Options{
		Now: result.Now,
		CA:  result.TestCA,
		Root: testsign.KeyInfo{
			CommonName:     "GCE-cc-tcb-root",
			KeyVersionName: "projects/testProject/locations/us-west1/keyRings/gce-cc-ring/cryptoKeys/gce-cc-tcb-root/cryptoKeyVersions/1"},
		PrimarySigningKey: testsign.KeyInfo{
			CommonName:     "GCE-uefi-signer",
			KeyVersionName: SignKey,
		},
		SigningKeys: []testsign.KeyInfo{{
			CommonName:     "Unused",
			KeyVersionName: "unused-key",
		}}})
	if err != nil {
		t.Fatal(err)
	}
	result.TestSigner = s
	result.TestCA.PrimarySigningKey = SignKey

	if !result.Rot.AppendCertsFromPEM(devkeys.RootCert) {
		t.Fatal("could not append root devkey cert")
	}
	return result
}

// FakeEndorsement returns a signed endorsement of the 2MiB 1 VMSA clean example.
func FakeEndorsement(t testing.TB) []byte {
	dir := t.TempDir()
	c := cmd.Compose(memkm.TestOnlyT(), memca.TestOnlyCertificateAuthority(), &localnonvcs.T{Root: dir})
	app := cmd.MakeApp(context.Background(), &cmd.AppComponents{Endorse: c})
	fw := fakeovmf.CleanExample(t, 2*1024*1024)
	fwPath := path.Join(dir, "ovmf_x64_csm.fd")
	if err := os.WriteFile(fwPath, fw, 0644); err != nil {
		t.Fatal(err)
	}
	app.SetArgs([]string{"endorse", "--verbose", "--uefi", fwPath,
		"--out_dir", dir,
		"--commit=988881adc9fc3655077dc2d4d757d480b5ea0e11",
		"--add_snp", "--add_tdx"})
	if err := app.Execute(); err != nil {
		t.Fatal(err)
	}
	endorsement, err := os.ReadFile(path.Join(dir, "endorsement.binarypb"))
	if err != nil {
		t.Fatal(err)
	}
	return endorsement
}
