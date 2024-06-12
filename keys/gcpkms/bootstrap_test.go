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

package gcpkms

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/google/gce-tcb-verifier/cmd/output"
	"github.com/google/gce-tcb-verifier/keys"
	"github.com/google/gce-tcb-verifier/rotate"
	"github.com/google/gce-tcb-verifier/sign/gcsca"
	sops "github.com/google/gce-tcb-verifier/sign/ops"
	styp "github.com/google/gce-tcb-verifier/sign/types"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/gce-tcb-verifier/testing/storage"
	"github.com/google/gce-tcb-verifier/testing/testsign"
	"github.com/google/gce-tcb-verifier/timeproto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCreateNewHSMKey(t *testing.T) {
	ctx0, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	now := time.Now()
	expectedResponse := &kmspb.CryptoKey{
		Name:       "some/kinda/key/path",
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		CreateTime: timeproto.To(now),
		Primary: &kmspb.CryptoKeyVersion{
			Name:       "some/kinda/key/path/v0",
			CreateTime: timeproto.To(now),
			Algorithm:  kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		},
	}
	mockKeyManagement.CreateCryptoKeyResp = map[string]*kmspb.CryptoKey{
		"root": expectedResponse,
	}

	m := &Manager{
		Project:   "proj",
		Location:  "loc",
		KeyRingID: "keyRing",
		KeyClient: kmspb.NewKeyManagementServiceClient(conn),
		IAMClient: iampb.NewIAMPolicyClient(conn),
	}
	ctx := keys.NewContext(ctx0, &keys.Context{
		Manager: m,
	})
	err := m.createNewHSMKey(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
}

type nopMutation struct{}

func (*nopMutation) SetPrimaryRootKeyVersion(string)             {}
func (*nopMutation) SetPrimarySigningKeyVersion(string)          {}
func (*nopMutation) AddSigningKeyCert(string, *x509.Certificate) {}
func (*nopMutation) SetRootKeyCert(*x509.Certificate)            {}

func TestSelfSignRootKey(t *testing.T) {
	mu.Do(initRoot(t))

	ctx0 := context.Background()

	keyClient := kmspb.NewKeyManagementServiceClient(conn)
	m := &Manager{
		Project:   "proj",
		Location:  "loc",
		KeyRingID: "keyRing",
		KeyClient: keyClient,
		IAMClient: iampb.NewIAMPolicyClient(conn),
	}

	ctx1 := rotate.NewBootstrapContext(ctx0, &rotate.BootstrapContext{
		RootKeyCommonName: styp.RootCommonName,
		RootKeySerial:     big.NewInt(1),
	})

	template, err := m.CertificateTemplate(ctx1, nil, &signer.Keys[rootVersion1].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCertG, err := sops.CreateCertificateFromTemplate(ctx1, &sops.CertRequest{
		Random:               testsign.RootRand(),
		Signer:               signer,
		Template:             template,
		IssuerKeyVersionName: rootVersion1,
	})
	if err != nil {
		t.Fatal(err)
	}

	mockKeyManagement.AddPKResponse(rootVersion1, signer, t)
	mockKeyManagement.AddKmsSignatureResponse(rootCertG.RawTBSCertificate, rootCertG.Signature)

	ctx2 := NewBootstrapContext(ctx1, &BootstrapContext{
		RootKeyID:           "root",
		SigningKeyOperators: []string{"example@example.com"},
	})
	ctx := keys.NewContext(ctx2, &keys.Context{
		Random:  testsign.RootRand(),
		Signer:  &Signer{Manager: m},
		Manager: m,
	})
	got, err := rotate.InternalSignAndUpload(ctx, &rotate.InternalSignAndUploadRequest{
		Mutation:              &nopMutation{},
		SubjectKeyVersionName: rootVersion1,
		IssuerKeyVersionName:  rootVersion1,
	})
	if err != nil {
		t.Fatalf("selfSignRootKey(_, _, %q, %q) = %v", styp.RootCommonName, rootVersion1, err)
	}
	if err := got.CheckSignatureFrom(got); err != nil {
		t.Errorf("Key is not self-signed: %v", err)
	}
}

func TestCreateKeyAssets(t *testing.T) {
	ctx0, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	mu.Do(initRoot(t))

	now := time.Date(2022, time.November, 16, 0, 0, 0, 0, time.UTC)

	bc := &rotate.BootstrapContext{
		RootKeyCommonName:    styp.RootCommonName,
		SigningKeyCommonName: styp.UEFISigningCommonName,
	}
	ctx1 := rotate.NewBootstrapContext(ctx0, bc)
	m := &Manager{
		Project:   "test-project",
		Location:  "us-west1",
		KeyRingID: "test-key-ring",
		KeyClient: kmspb.NewKeyManagementServiceClient(conn),
		IAMClient: iampb.NewIAMPolicyClient(conn),
	}
	ctx2 := NewBootstrapContext(ctx1, &BootstrapContext{
		RootKeyID:    "test-root-key",
		SigningKeyID: "test-signing-key",
	})

	rootFullName := m.FullKeyName("test-root-key")
	signingFullName := m.FullKeyName("test-signing-key")
	rootPEM, err := ca.CABundle(ctx1, signingFullName)
	if err != nil {
		t.Fatal("no root cert")
	}
	ca := &testsign.MockSigner{CABundles: map[string][]byte{rootVersion1: rootPEM}}
	ctx3 := NewBootstrapContext(ctx2, &BootstrapContext{
		RootKeyID:           "test-root-key",
		SigningKeyID:        "test-signing-key",
		SigningKeyOperators: []string{"example@example.com"},
	})
	ctx := keys.NewContext(ctx3, &keys.Context{
		Random:  testsign.RootRand(),
		Manager: m,
		CA:      ca,
		Signer:  signer,
	})
	// Prepare responses for CreateKeyRing, create root key, create signing key.
	mockKeyManagement.Resps = append(mockKeyManagement.Resps[:0],
		// CreateKeyRing
		&kmspb.KeyRing{
			Name:       "projects/test-project/locations/us-west1/keyRings/test-key-ring",
			CreateTime: timeproto.To(now),
		})
	mockKeyManagement.CreateCryptoKeyResp = map[string]*kmspb.CryptoKey{
		"test-root-key": {
			Name:       rootFullName,
			CreateTime: timeproto.To(now),
			Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN},
		"test-signing-key": {
			Name:                     signingFullName,
			CreateTime:               timeproto.To(now),
			DestroyScheduledDuration: destroyScheduledDuration,
			Purpose:                  kmspb.CryptoKey_ASYMMETRIC_SIGN,
		},
	}
	fmt.Println("Setting up list for", rootFullName, signingFullName)
	mockKeyManagement.ListCryptoKeyVersionsResp = map[string]*kmspb.ListCryptoKeyVersionsResponse{
		rootFullName: {
			CryptoKeyVersions: []*kmspb.CryptoKeyVersion{
				{Name: rootVersion1, State: kmspb.CryptoKeyVersion_PENDING_GENERATION},
			},
			TotalSize: 1,
		},
		signingFullName: {
			CryptoKeyVersions: []*kmspb.CryptoKeyVersion{
				{Name: signingVersionName, State: kmspb.CryptoKeyVersion_PENDING_GENERATION},
			},
			TotalSize: 1,
		},
	}
	mockKeyManagement.GetCryptoKeyVersionResp = map[string]*kmspb.CryptoKeyVersion{
		rootVersion1:       {Name: rootVersion1, State: kmspb.CryptoKeyVersion_ENABLED},
		signingVersionName: {Name: signingVersionName, State: kmspb.CryptoKeyVersion_ENABLED},
	}
	rootKeyVersion, err := m.CreateNewRootKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rootKeyVersion != rootVersion1 {
		t.Errorf("m.CreateNewRootKey(...) = &CryptoKey{Name: %q, ...}, _, _ want %q", rootKeyVersion, rootVersion1)
	}
	signingKeyVersion, err := m.CreateFirstSigningKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if signingKeyVersion != signingVersionName {
		t.Errorf("m.CreateFirstSigningKey(...) = _, &CryptoKey{Name: %q, ...}, want %q", signingKeyVersion, signingVersionName)
	}
}

func TestCreateKeyAssetsWhenKeyRingExists(t *testing.T) {
	ctx0, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	mu.Do(initRoot(t))

	now := time.Date(2022, time.November, 16, 0, 0, 0, 0, time.UTC)

	bc := &rotate.BootstrapContext{
		RootKeyCommonName:    styp.RootCommonName,
		RootKeySerial:        big.NewInt(1),
		SigningKeyCommonName: styp.UEFISigningCommonName,
		SigningKeySerial:     big.NewInt(2),
	}
	ctx1 := rotate.NewBootstrapContext(ctx0, bc)
	m := &Manager{
		Project:   "test-project",
		Location:  "us-west1",
		KeyRingID: "test-key-ring",
		KeyClient: kmspb.NewKeyManagementServiceClient(conn),
		IAMClient: iampb.NewIAMPolicyClient(conn),
	}
	ctx2 := NewBootstrapContext(ctx1, &BootstrapContext{
		RootKeyID:    "test-root-key",
		SigningKeyID: "test-signing-key",
	})
	rand := testsign.RootRand()
	// We can't use signer's self-created certificates since they use the wrong template.
	rootCert, err := sops.GoogleCertificate(ctx2, &sops.GoogleCertRequest{
		Template: &sops.GoogleCertTemplate{
			PublicKey:         &signer.Keys[rootVersion1].PublicKey,
			Serial:            bc.RootKeySerial,
			SubjectCommonName: styp.RootCommonName,
			NotBefore:         now,
		},
		Random:               rand,
		Signer:               signer,
		IssuerKeyVersionName: rootVersion1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ca := &testsign.MockSigner{CABundles: map[string][]byte{
		rootVersion1: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rootCert.Raw,
		})}}
	rctx := &keys.Context{
		Random:  testsign.RootRand(),
		CA:      ca,
		Signer:  signer,
		Manager: m,
	}
	ctx3 := keys.NewContext(ctx2, rctx)
	mockKeyManagement.Clear()
	// Prepare responses for CreateKeyRing, create root key, create signing key.
	mockKeyManagement.CreateKeyRingErr = status.Error(codes.AlreadyExists, "")
	if _, err = m.CreateNewRootKey(ctx3); status.Code(err) != codes.AlreadyExists {
		t.Errorf("m.CreateNewRootKey(...) = _, _, %v want AlreadyExists error", err)
	}

	// Now make progress past the alreadyexists for the root key.
	ctx := output.NewContext(ctx3, &output.Options{Overwrite: true})
	mockKeyManagement.Resps = append(mockKeyManagement.Resps[:0],
		// GetKeyRing
		&kmspb.KeyRing{
			Name:       "projects/test-project/locations/us-west1/keyRings/test-key-ring",
			CreateTime: timeproto.To(now),
		})

	mockKeyManagement.CreateKeyRingErr = nil
	mockKeyManagement.CreateCryptoKeyErr = map[string]error{
		"test-root-key": status.Error(codes.PermissionDenied, ""),
	}
	if k, err := m.CreateNewRootKey(ctx); status.Code(err) != codes.PermissionDenied {
		t.Errorf("m.CreateNewRootKey(ctx) = %v, %v want PermissionDenied error", k, err)
	}
}

func TestBootstrapEnsureBucketWithNoPermissions(t *testing.T) {
	bc := &rotate.BootstrapContext{Now: time.Now()}
	ctx0 := context.Background()
	ctx1 := rotate.NewBootstrapContext(ctx0, bc)
	rctx := &keys.Context{
		CA: &testsign.MockSigner{PrepareErr: os.ErrPermission},
	}
	ctx := keys.NewContext(ctx1, rctx)
	want := "could not prepare certificate authority resources"
	if err := rotate.Bootstrap(ctx); !match.Error(err, want) {
		t.Errorf("Bootstrap(_) = %v, want %q", err, want)
	}
}

func TestCreateKeyAssetsWhenKeyRingAndRootKeyExist(t *testing.T) {
	ctx0, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	mu.Do(initRoot(t))

	now := time.Date(2022, time.November, 16, 0, 0, 0, 0, time.UTC)

	m := &Manager{
		Project:   "test-project",
		Location:  "us-west1",
		KeyRingID: "test-key-ring",
		KeyClient: kmspb.NewKeyManagementServiceClient(conn),
		IAMClient: iampb.NewIAMPolicyClient(conn),
	}
	bc := &rotate.BootstrapContext{
		RootKeyCommonName:    styp.RootCommonName,
		RootKeySerial:        big.NewInt(1),
		SigningKeyCommonName: styp.UEFISigningCommonName,
	}
	ctx1 := rotate.NewBootstrapContext(ctx0, bc)
	ctx2 := NewBootstrapContext(ctx1, &BootstrapContext{
		RootKeyID:    "test-root-key",
		SigningKeyID: "test-signing-key",
	})
	rand := testsign.RootRand()
	// We can't use signer's self-created certificates since they use the wrong template.
	rootCert, err := sops.GoogleCertificate(ctx2, &sops.GoogleCertRequest{
		Template: &sops.GoogleCertTemplate{
			PublicKey:         &signer.Keys[rootVersion1].PublicKey,
			Serial:            bc.RootKeySerial,
			SubjectCommonName: styp.RootCommonName,
			NotBefore:         now,
		},
		Random:               rand,
		Signer:               signer,
		IssuerKeyVersionName: rootVersion1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ca := &testsign.MockSigner{CABundles: map[string][]byte{
		rootVersion1: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rootCert.Raw,
		})}}
	rctx := &keys.Context{
		Random:  testsign.RootRand(),
		CA:      ca,
		Signer:  signer,
		Manager: m,
	}
	ctx3 := keys.NewContext(ctx2, rctx)
	mockKeyManagement.Clear()
	// Prepare responses for CreateKeyRing, create root key, create signing key.
	mockKeyManagement.CreateKeyRingErr = status.Error(codes.AlreadyExists, "")
	if _, err := m.CreateNewRootKey(ctx3); status.Code(err) != codes.AlreadyExists {
		t.Errorf("m.CreateNewRootKey(...) = _, _, %v want AlreadyExists error", err)
	}

	// Now make progress past the alreadyexists
	ctx := output.NewContext(ctx3, &output.Options{KeepGoing: true, Overwrite: true})
	mockKeyManagement.Resps = append(mockKeyManagement.Resps[:0],
		// GetKeyRing
		&kmspb.KeyRing{
			Name:       "projects/test-project/locations/us-west1/keyRings/test-key-ring",
			CreateTime: timeproto.To(now),
		})

	mockKeyManagement.CreateCryptoKeyErr = map[string]error{
		"test-root-key":    status.Error(codes.AlreadyExists, ""),
		"test-signing-key": status.Error(codes.PermissionDenied, ""),
	}
	rootFullName := m.FullKeyName("test-root-key")
	mockKeyManagement.GetCryptoKeyResp = map[string]*kmspb.CryptoKey{
		rootFullName: {Name: rootFullName, CreateTime: timeproto.To(now)},
	}
	mockKeyManagement.ListCryptoKeyVersionsResp = map[string]*kmspb.ListCryptoKeyVersionsResponse{
		rootFullName: {
			CryptoKeyVersions: []*kmspb.CryptoKeyVersion{
				{
					Name:  rootVersion1,
					State: kmspb.CryptoKeyVersion_ENABLED,
				},
			},
			TotalSize: 1,
		},
	}
	mockKeyManagement.AddPKResponse(rootVersion1, signer, t)
	mockKeyManagement.CreateKeyRingErr = nil
	if k, err := m.CreateNewRootKey(ctx); err != nil {
		t.Errorf("m.CreateNewRootKey(...) = %v, %v want nil", k, err)
	}
	if k, err := m.CreateFirstSigningKey(ctx); status.Code(err) != codes.PermissionDenied {
		t.Errorf("m.CreateFirstSigningKey(...) = %v, %v want PermissionDenied error", k, err)
	}
}

type bootStrapValues struct {
	ctx            context.Context
	ca             *gcsca.CertificateAuthority
	signingKeyCert *x509.Certificate
	now            time.Time
}

func setupBootstrap(t *testing.T) (*bootStrapValues, context.CancelFunc) {
	mu.Do(initRoot(t))

	r := &bootStrapValues{}
	ctx0, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	// Prepare the same responses as CreateKeyAssets, but add more for the signing.
	// Expect that the root key signature, the signing key signature, and the key manifest all get
	// written to the private bucket.
	storage := storage.WithInitialContents(map[string][]byte{
		gcsca.ManifestObjectName: []byte(fmt.Sprintf(`primary_root_key_version_name: %q`, rootVersion1)),
	}, "test")

	r.now = time.Date(2022, time.November, 16, 0, 0, 0, 0, time.UTC)

	bc := &rotate.BootstrapContext{
		RootKeyCommonName:    styp.RootCommonName,
		RootKeySerial:        big.NewInt(1),
		SigningKeyCommonName: styp.UEFISigningCommonName,
		SigningKeySerial:     big.NewInt(2),
		Now:                  time.Date(2022, time.November, 16, 0, 0, 0, 0, time.UTC),
	}
	ctx1 := rotate.NewBootstrapContext(ctx0, bc)
	ctx2 := NewBootstrapContext(
		ctx1, &BootstrapContext{
			SigningKeyOperators: []string{"ignore"},
		})
	keyClient := kmspb.NewKeyManagementServiceClient(conn)
	m := &Manager{
		Project:   "test-project",
		Location:  "us-west1",
		KeyRingID: "test-key-ring",
		KeyClient: keyClient,
		IAMClient: iampb.NewIAMPolicyClient(conn),
	}

	ksigner := &Signer{Manager: m}
	r.ca = &gcsca.CertificateAuthority{
		Storage:             storage,
		PrivateBucket:       "test",
		SigningCertDirInGCS: "certs",
		RootPath:            "cvm-fw-root.crt",
	}
	c := &keys.Context{
		Random:  testsign.RootRand(),
		CA:      r.ca,
		Signer:  ksigner,
		Manager: m,
	}
	ctx3 := NewBootstrapContext(
		ctx2, &BootstrapContext{
			RootKeyID:    "test-root-key",
			SigningKeyID: "test-signing-key",
		})
	r.ctx = keys.NewContext(ctx3, c)
	rand := testsign.RootRand()
	// We can't use signer's self-created certificates since they use the wrong template.
	rootCert, err := sops.GoogleCertificate(r.ctx, &sops.GoogleCertRequest{
		Template: &sops.GoogleCertTemplate{
			Serial:            bc.RootKeySerial,
			PublicKey:         &signer.Keys[rootVersion1].PublicKey,
			SubjectCommonName: styp.RootCommonName,
			NotBefore:         bc.Now,
		},
		IssuerKeyVersionName: rootVersion1,
		Random:               rand,
		Signer:               signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatalf("root CreateCertificate: %v", err)
	}
	// Continue using rand since Bootstrap continues to use the same source of randomness.
	signingKeyCert, err := sops.GoogleCertificate(r.ctx, &sops.GoogleCertRequest{
		Template: &sops.GoogleCertTemplate{
			Serial:            bc.SigningKeySerial,
			PublicKey:         &signer.Keys[signingVersionName].PublicKey,
			Issuer:            rootCert,
			SubjectCommonName: styp.UEFISigningCommonName,
			NotBefore:         bc.Now,
		},
		IssuerKeyVersionName: rootVersion1,
		Signer:               signer,
		Random:               rand,
	})
	if err != nil {
		t.Fatalf("signer CreateCertificate: %v", err)
	}
	r.signingKeyCert = signingKeyCert

	// Prepare responses for CreateKeyRing, create root key, create signing key.
	mockKeyManagement.Clear()
	mockKeyManagement.Resps = append(mockKeyManagement.Resps[:0],
		// CreateKeyRing
		&kmspb.KeyRing{
			Name:       keyRingName,
			CreateTime: timeproto.To(now),
		})
	mockKeyManagement.AddPKResponse(rootVersion1, signer, t)
	mockKeyManagement.AddPKResponse(signingVersionName, signer, t)
	signingKeyPEM := mockKeyManagement.Resps[len(mockKeyManagement.Resps)-1].(*kmspb.PublicKey).GetPem()
	// Signing the primary key will mean getting the public key of its primary version first.
	mockKeyManagement.Resps = append(mockKeyManagement.Resps, &kmspb.PublicKey{
		Name: signingVersionName,
		Pem:  signingKeyPEM})
	mockKeyManagement.AddKmsSignatureResponse(rootCert.RawTBSCertificate, rootCert.Signature)
	mockKeyManagement.AddKmsSignatureResponse(signingKeyCert.RawTBSCertificate, signingKeyCert.Signature)
	signingCryptoKey := &kmspb.CryptoKey{
		Name:                     signingName,
		CreateTime:               timeproto.To(now),
		DestroyScheduledDuration: destroyScheduledDuration,
		Purpose:                  kmspb.CryptoKey_ASYMMETRIC_SIGN,
	}
	mockKeyManagement.GetCryptoKeyResp = map[string]*kmspb.CryptoKey{
		signingName: signingCryptoKey,
	}

	mockKeyManagement.CreateCryptoKeyResp = map[string]*kmspb.CryptoKey{
		"test-root-key": {
			Name:       rootName,
			CreateTime: timeproto.To(now),
			Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN},
		"test-signing-key": signingCryptoKey,
	}
	mockKeyManagement.ListCryptoKeyVersionsResp = map[string]*kmspb.ListCryptoKeyVersionsResponse{
		rootName: {
			CryptoKeyVersions: []*kmspb.CryptoKeyVersion{
				{Name: rootVersion1, State: kmspb.CryptoKeyVersion_ENABLED},
			},
			TotalSize: 1,
		},
		signingName: {
			CryptoKeyVersions: []*kmspb.CryptoKeyVersion{
				{Name: signingVersionName, State: kmspb.CryptoKeyVersion_ENABLED},
			},
			TotalSize: 1,
		},
	}
	return r, cancel
}

func TestBootstrap(t *testing.T) {
	b, cancel := setupBootstrap(t)
	defer cancel()

	if err := rotate.Bootstrap(b.ctx); err != nil {
		t.Fatal(err)
	}
	got, err := b.ca.Certificate(b.ctx, signingVersionName)
	if err != nil {
		t.Fatal(err)
	}
	want := b.signingKeyCert.Raw
	if !bytes.Equal(got, want) {
		t.Fatalf("ca.Certificate(_, %q) = %v, want %v", signingVersionName, got, want)
	}
}

func TestWipeoutAfterBootstrap(t *testing.T) {
	b, cancel := setupBootstrap(t)
	defer cancel()

	if err := rotate.Bootstrap(b.ctx); err != nil {
		t.Fatal(err)
	}
	// List all keys, list all versions, and respond to each version destroy request.
	mockKeyManagement.Resps = append(mockKeyManagement.Resps[:0],
		&kmspb.ListCryptoKeysResponse{
			CryptoKeys: []*kmspb.CryptoKey{
				{Name: rootName},
				{Name: signingName},
			}},
	)
	mockKeyManagement.ListCryptoKeyVersionsResp = map[string]*kmspb.ListCryptoKeyVersionsResponse{
		rootName: {
			TotalSize: 3,
			CryptoKeyVersions: []*kmspb.CryptoKeyVersion{
				{Name: rootVersion1, State: kmspb.CryptoKeyVersion_DESTROYED},
				{Name: rootVersion2, State: kmspb.CryptoKeyVersion_ENABLED},
				{Name: rootVersion3, State: kmspb.CryptoKeyVersion_DISABLED},
				{Name: "nope4", State: kmspb.CryptoKeyVersion_DESTROY_SCHEDULED},
				{Name: "nope5", State: kmspb.CryptoKeyVersion_PENDING_GENERATION},
				{Name: "nope6", State: kmspb.CryptoKeyVersion_PENDING_IMPORT},
				{Name: "nope7", State: kmspb.CryptoKeyVersion_IMPORT_FAILED},
				{Name: "nope8", State: kmspb.CryptoKeyVersion_GENERATION_FAILED},
				{Name: "nope9", State: kmspb.CryptoKeyVersion_PENDING_EXTERNAL_DESTRUCTION},
				{Name: "nope0", State: kmspb.CryptoKeyVersion_EXTERNAL_DESTRUCTION_FAILED},
			}},
		// Ensure 0 versions are also acceptable.
		signingName: {},
	}
	// The destroyed version will not be requested to be destroyed.
	mockKeyManagement.DestroyCryptoKeyVersionResp = map[string]*kmspb.CryptoKeyVersion{
		rootVersion2: {Name: rootVersion2, State: kmspb.CryptoKeyVersion_DESTROY_SCHEDULED},
		rootVersion3: {Name: rootVersion3, State: kmspb.CryptoKeyVersion_DESTROYED},
	}
	if err := rotate.Wipeout(rotate.NewWipeoutContext(b.ctx, &rotate.WipeoutContext{CA: true, Keys: true})); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ca.Storage.Reader(b.ctx, "test", gcsca.ManifestObjectName); err == nil || !os.IsNotExist(err) {
		t.Fatalf("Wipeout(_) = %v. Want manifest to get wiped out", err)
	}
}
