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

package gcsca

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/gce-tcb-verifier/cmd/output"
	cpb "github.com/google/gce-tcb-verifier/proto/certificates"
	"github.com/google/gce-tcb-verifier/sign/memca"
	sops "github.com/google/gce-tcb-verifier/sign/ops"
	styp "github.com/google/gce-tcb-verifier/sign/types"
	"github.com/google/gce-tcb-verifier/storage/local"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/google/gce-tcb-verifier/testing/devkeys"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/gce-tcb-verifier/testing/storage"
	"github.com/google/gce-tcb-verifier/testing/testca"
	"github.com/google/gce-tcb-verifier/testing/testsign"
)

const keyObjPath = "certs/fr1st.crt"

var certDate = time.Date(2022, time.October, 20, 13, 0, 0, 0, time.UTC)

// Operations for testing

// ReadObjectForTest is a function only for tests that returns the raw contents of the object at
// a given path and errors if the length is not wantlen.
func readObjectForTest(ca *CertificateAuthority, path string, wantlen int) ([]byte, error) {
	r, err := ca.Storage.Reader(context.Background(), ca.PrivateBucket, path)
	if err != nil {
		return nil, fmt.Errorf("Object(%q).NewReader() returned unexpected error: %v", path, err)
	}
	got := make([]byte, 2*wantlen)
	n, err := r.Read(got[:])
	if err == io.EOF && wantlen == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%q.Read = %d, %v want %d, nil", path, n, err, wantlen)
	}
	return got[:n], nil
}

func assertMatchTextproto(path string, gotBytes, wantBytes []byte) error {
	// Don't compare whitespace-sensitive protos. Just unmarshal and compare.
	got := &cpb.GCECertificateManifest{}
	want := &cpb.GCECertificateManifest{}
	if err := multierr.Combine(
		prototext.Unmarshal(gotBytes, got),
		prototext.Unmarshal(wantBytes, want)); err != nil {
		return err
	}
	entryContained := func(want *cpb.GCECertificateManifest_Entry, entries []*cpb.GCECertificateManifest_Entry, name string) error {
		for _, has := range entries {
			if cmp.Equal(want, has, protocmp.Transform()) {
				return nil
			}
		}
		return fmt.Errorf("entry %v expected to be in %s. Contents are %+v", want, name, entries)
	}
	entriesContained := func(left, right []*cpb.GCECertificateManifest_Entry, rightName string) error {
		for _, want := range left {
			if err := entryContained(want, right, rightName); err != nil {
				return err
			}
		}
		return nil
	}
	if err := multierr.Combine(
		entriesContained(got.Entries, want.Entries, "want"),
		entriesContained(want.Entries, got.Entries, "got")); err != nil {
		return err
	}
	got.Entries = nil
	want.Entries = nil

	if diff := cmp.Diff(got, want, protocmp.Transform()); diff != "" {
		return fmt.Errorf("%q got %v want %v diff %s", path, string(gotBytes), string(wantBytes), diff)
	}
	return nil
}

// AssertMatchForTest is a function only for tests to compare expected contents at a given path.
func assertMatchForTest(ca *CertificateAuthority, path string, want []byte) error {
	got, err := readObjectForTest(ca, path, len(want))
	if err != nil {
		return err
	}
	if strings.HasSuffix(path, ".textproto") {
		if err := assertMatchTextproto(path, got, want); err != nil {
			return err
		}
	} else {
		if len(got) != len(want) {
			return fmt.Errorf("%q.Read = %d, %v want %d, nil", path, len(got), nil, len(want))
		}
		if diff := cmp.Diff(got, want); diff != "" {
			return fmt.Errorf("%q want are %v want %v diff %s", path, string(got), string(want), diff)
		}
	}
	return nil
}

func TestCertificate(t *testing.T) {
	keyVersionName := "projects/test-project/locations/us-west1/keyRings/test-keyring/cryptoKeys/test-signing-key/cryptoKeyVersions/123"
	bucketName := "test"
	storage := storage.WithInitialContents(map[string][]byte{
		"certs/signing-key.crt": devkeys.PrimarySigningKeyCert,
		ManifestObjectName: []byte(fmt.Sprintf(`entries {
					key_version_name: %q
					object_path: "certs/signing-key.crt"
				}`, keyVersionName)),
	}, bucketName)
	ctx := context.Background()
	ca := &CertificateAuthority{
		Storage:             storage,
		PrivateBucket:       bucketName,
		SigningCertDirInGCS: "certs",
		SigningKeyPrefix:    "projects/test-project/locations/us-west1/keyRings/test-keyring",
	}
	got, err := ca.Certificate(ctx, keyVersionName)
	if err != nil {
		t.Errorf("Certificate(%q) = %v, want nil", keyVersionName, err)
	}
	want := devkeys.PrimarySigningKeyCert
	if !bytes.Equal(got, want) {
		t.Errorf("Certificate(%q) = %v, want %v", keyVersionName, got, want)
	}
}

func TestCABundle(t *testing.T) {
	bucketName := "test"
	ctx := context.Background()
	storage := storage.WithInitialContents(map[string][]byte{
		"root-key.crt": []byte(`content`),
	}, bucketName)
	ca := &CertificateAuthority{
		RootPath:            "root-key.crt",
		Storage:             storage,
		PrivateBucket:       bucketName,
		SigningCertDirInGCS: "certs",
		SigningKeyPrefix:    "projects/test-project/locations/us-west1/keyRings/test-keyring",
	}
	tests := []struct {
		name           string
		keyVersionName string
		want           []byte
		wantErr        string
	}{
		{
			name:           "happy path",
			keyVersionName: "projects/test-project/locations/us-west1/keyRings/test-keyring/cryptoKeys/test-signing-key",
			want:           []byte(`content`),
		},
		{
			name:           "bad keyring",
			keyVersionName: "projects/test-project/locations/us-west1/keyRings/prod-keyring/cryptoKeys/test-signing-key",
			wantErr:        `key version "projects/test-project/locations/us-west1/keyRings/prod-keyring/cryptoKeys/test-signing-key" does not have expected prefix "projects/test-project/locations/us-west1/keyRings/test-keyring"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ca.CABundle(ctx, tc.keyVersionName)
			if !match.Error(err, tc.wantErr) {
				t.Fatalf("CABundle(%q) = %v, want %q", tc.keyVersionName, err, tc.wantErr)
			}
			if tc.wantErr == "" && !bytes.Equal(got, tc.want) {
				t.Errorf("CABundle(%q) = %v, want %v", tc.keyVersionName, got, tc.want)
			}
		})
	}
}

func testData(initialObjects map[string][]byte) *CertificateAuthority {
	storage := storage.WithInitialContents(initialObjects, "test")
	return &CertificateAuthority{
		Storage:             storage,
		PrivateBucket:       "test",
		SigningCertDirInGCS: "certs",
	}
}

// The input isn't an x509.Certificate, so just treat it like the Raw x509 certificate data.
func derCert(data []byte) []byte {
	return data
}

func TestUploadToPrivate(t *testing.T) {
	initialManifest := `entries: {
		key_version_name: "key"
		object_path: "certs/fr1st.crt"
	}`
	ctx := context.Background()

	manifestContents := []byte(initialManifest)
	keyObjContents := []byte("first contents")
	inside := []byte("inside the file")
	mkCert := func(commonName, serial string) (*x509.Certificate, string) {
		return &x509.Certificate{
			Subject:   pkix.Name{CommonName: commonName, SerialNumber: serial},
			Raw:       inside,
			NotBefore: certDate,
		}, fmt.Sprintf("certs/%s-%s.crt", commonName, serial)
	}
	newCert0, certPath0 := mkCert(styp.UEFISigningCommonName, "1234")
	newCert1, certPath1 := mkCert("GCE-svsm-signing-key", "5678")
	basicInitialObjects := map[string][]byte{
		keyObjPath:         keyObjContents,
		ManifestObjectName: manifestContents,
	}
	tests := []struct {
		name           string
		ctx            context.Context
		keyVersionName string
		cert           *x509.Certificate
		wantErr        string
		prefix         string
		initialObjects map[string][]byte // All bucket "test"
		wantPrivate    map[string][]byte
	}{
		{
			name:           "happy path UEFI",
			keyVersionName: "key0",
			cert:           newCert0,
			prefix:         "gce-uefi-signer",
			initialObjects: basicInitialObjects,
			wantPrivate: map[string][]byte{
				certPath0:          derCert(inside),
				ManifestObjectName: testsign.ExtendManifest(initialManifest, "key0", certPath0, ""),
			},
		},
		{
			name:           "happy path SVSM",
			keyVersionName: "key1",
			cert:           newCert1,
			prefix:         "gce-svsm-signer",
			initialObjects: basicInitialObjects,
			wantPrivate: map[string][]byte{
				certPath1:          derCert(inside),
				ManifestObjectName: testsign.ExtendManifest(initialManifest, "key1", certPath1, ""),
			},
		},
		{
			name:           "happy path empty manifest",
			keyVersionName: "key0",
			cert:           newCert0,
			initialObjects: map[string][]byte{keyObjPath: keyObjContents},
			prefix:         "gce-uefi-signer",
			wantPrivate: map[string][]byte{
				certPath0:          derCert(inside),
				ManifestObjectName: testsign.ExtendManifest("", "key0", certPath0, ""),
			},
		},
		{
			name:           "used key",
			keyVersionName: "key",
			cert:           &x509.Certificate{},
			prefix:         "ignored",
			initialObjects: map[string][]byte{
				"certs/fr1st.crt":  {0xf},
				ManifestObjectName: manifestContents,
			},
			wantErr: "exists",
		},
		{
			name:           "used key keep going",
			keyVersionName: "key",
			cert:           &x509.Certificate{},
			prefix:         "ignored",
			initialObjects: map[string][]byte{ManifestObjectName: manifestContents},
			ctx:            output.NewContext(ctx, &output.Options{KeepGoing: true}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tcctx := context.Background()
			if tc.ctx != nil {
				tcctx = tc.ctx
			}
			ca := testData(tc.initialObjects)
			mut := ca.NewMutation()
			mut.AddSigningKeyCert(tc.keyVersionName, tc.cert)
			if err := ca.Finalize(tcctx, mut); !match.Error(err, tc.wantErr) {
				t.Errorf("Finalize(_, AddSigningKeyCert(%q, %v)) = %v, want %q", tc.keyVersionName, tc.cert, err, tc.wantErr)
			}
			for path, contents := range tc.wantPrivate {
				if err := assertMatchForTest(ca, path, contents); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

const (
	rootCommon         = styp.RootCommonName
	signingCommon      = styp.UEFISigningCommonName
	rotatedCommon      = "rotated-key"
	keyRingName        = "projects/test-project/locations/us-west1/keyRings/test-key-ring"
	rootName           = keyRingName + "/cryptoKeys/test-root-key"
	rootVersion1       = rootName + "/cryptoKeyVersions/1"
	signingName        = keyRingName + "/cryptoKeys/test-signing-key"
	rotatedName        = signingName + "/cryptoKeyVersions/2"
	signingVersionName = signingName + "/cryptoKeyVersions/1"
)

func TestCertObjectName(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	signer, err := testsign.MakeSigner(ctx, &testsign.Options{
		Now:               now,
		CA:                memca.Create(),
		Root:              testsign.KeyInfo{CommonName: rootCommon, KeyVersionName: rootVersion1},
		PrimarySigningKey: testsign.KeyInfo{CommonName: signingCommon, KeyVersionName: signingVersionName},
		SigningKeys:       []testsign.KeyInfo{{CommonName: rotatedCommon, KeyVersionName: rotatedName}}})
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := sops.GoogleCertificate(ctx, &sops.GoogleCertRequest{
		Template: &sops.GoogleCertTemplate{
			Serial:            big.NewInt(1),
			PublicKey:         &signer.Keys[rootVersion1].PublicKey,
			SubjectCommonName: rootCommon,
			NotBefore:         now,
		},
		Random:               testsign.RootRand(),
		IssuerKeyVersionName: rootVersion1,
		Signer:               signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	rotatedCert, err := sops.GoogleCertificate(ctx, &sops.GoogleCertRequest{
		Template: &sops.GoogleCertTemplate{

			Serial:            big.NewInt(3),
			PublicKey:         &signer.Keys[rotatedName].PublicKey,
			Issuer:            rootCert,
			SubjectCommonName: rotatedCommon,
		},
		IssuerKeyVersionName: rootVersion1,
		Random:               testsign.SignerRand(),
		Signer:               signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "certs/rotated-key-3.crt"
	got := (&CertificateAuthority{SigningCertDirInGCS: "certs"}).certObjectName(rotatedCert)
	if got != want {
		t.Errorf("certObjectName(%v) = %q, want %q", rotatedCert, got, want)
	}
}

func TestMutations(t *testing.T) {
	now := time.Now()
	bucket := "test"
	maxSigningKeys := 10
	var signingKeyNames []testsign.KeyInfo
	for i := 0; i < maxSigningKeys; i++ {
		signingKeyNames = append(signingKeyNames,
			testsign.KeyInfo{
				CommonName:     signingCommon,
				KeyVersionName: fmt.Sprintf("%s/cryptoKeyVersions/%d", signingName, i+1),
			})
	}
	s := storage.WithInitialContents(map[string][]byte{}, bucket)
	ca := &CertificateAuthority{
		RootPath:            "cvm-fw-root.crt",
		SigningCertDirInGCS: "certs",
		SigningKeyPrefix:    keyRingName,
		PrivateBucket:       bucket,
		Storage:             s,
	}
	_, err := testsign.MakeSigner(context.Background(), &testsign.Options{
		Now:               now,
		CA:                ca,
		Root:              testsign.KeyInfo{CommonName: rootCommon, KeyVersionName: rootVersion1},
		PrimarySigningKey: signingKeyNames[0],
		SigningKeys:       signingKeyNames[1:],
	})
	if err != nil {
		t.Fatal(err)
	}

	b := &cpb.GCECertificateManifest{}
	b.PrimaryRootKeyVersionName = rootVersion1
	b.PrimarySigningKeyVersionName = signingVersionName
	for i := 0; i < maxSigningKeys; i++ {
		name := fmt.Sprintf("%s/cryptoKeyVersions/%d", signingName, i+1)
		b.Entries = append(b.Entries, &cpb.GCECertificateManifest_Entry{
			KeyVersionName: name,
			ObjectPath:     fmt.Sprintf("certs/GCE-uefi-signing-key-%d.crt", i+2),
		})
	}
	manifest, _ := prototext.Marshal(b)
	if err := assertMatchForTest(ca, ManifestObjectName, manifest); err != nil {
		t.Fatal(err)
	}
	// Expect the root cert to have been written.
	bundle, err := ca.CABundle(context.Background(), signingName)
	if err != nil {
		t.Fatalf("ca.CABundle(_, %q) = _, %v, want nil", signingName, err)
	}
	rootCrt, ok := s.BucketObjects[bucket]["cvm-fw-root.crt"]
	if !ok || rootCrt.Cell == nil || len(rootCrt.Cell.Data) == 0 {
		t.Fatal("root cert was not written to storage")
	}
	want := rootCrt.Cell.Data
	if !bytes.Equal(bundle, want) {
		t.Fatalf("Root cert contents %v, want %v", string(bundle), string(want))
	}
	for i := 0; i < maxSigningKeys; i++ {
		name := fmt.Sprintf("%s/cryptoKeyVersions/%d", signingName, i+1)
		objName := fmt.Sprintf("certs/GCE-uefi-signing-key-%d.crt", i+2)
		want := derCert(s.BucketObjects[bucket][objName].Cell.Data)
		got, err := readObjectForTest(ca, objName, len(want))
		if err != nil {
			t.Fatalf("Signing key cert %q read failed: %v", objName, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("Signing key %q cert contents %v, want %v", name, got, want)
		}
	}
}

func mkLocalGcsca(t testing.TB) *CertificateAuthority {
	t.Helper()
	return &CertificateAuthority{
		Storage:             &local.StorageClient{Root: t.TempDir()},
		PrivateBucket:       "test",
		SigningCertDirInGCS: "certs",
		RootPath:            "root.crt",
	}
}

func TestGcscaLocalStorageSetGetRootName(t *testing.T) {
	testca.SetGetRootName(context.Background(), t, mkLocalGcsca(t))
}

func TestGcscaLocalStorageSetGetPrimarySigningKeyName(t *testing.T) {
	testca.SetGetPrimarySigningKeyName(context.Background(), t, mkLocalGcsca(t))
}

func TestGcscaLocalStorageSetGetRootCert(t *testing.T) {
	testca.SetGetRootCert(context.Background(), t, mkLocalGcsca(t))
}

func TestGcscaLocalStorageAddSigningKeyCert(t *testing.T) {
	testca.AddGetSigningKeyCert(context.Background(), t, mkLocalGcsca(t))
}

func TestGcscaLocalStorageWipeout(t *testing.T) {
	testca.Wipeout(context.Background(), t, mkLocalGcsca(t))
}
