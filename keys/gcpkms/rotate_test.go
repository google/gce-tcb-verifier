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
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/google/gce-tcb-verifier/keys"
	"github.com/google/gce-tcb-verifier/rotate"
	"github.com/google/gce-tcb-verifier/sign/gcsca"
	"github.com/google/gce-tcb-verifier/sign/memca"
	"github.com/google/gce-tcb-verifier/sign/nonprod"
	sops "github.com/google/gce-tcb-verifier/sign/ops"
	styp "github.com/google/gce-tcb-verifier/sign/types"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/gce-tcb-verifier/testing/storage"
	"github.com/google/gce-tcb-verifier/testing/testkms"
	"github.com/google/gce-tcb-verifier/testing/testsign"
	"google.golang.org/grpc"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	rootCommon         = styp.RootCommonName
	signingCommon      = styp.UEFISigningCommonName
	rotatedCommon      = "rotated-key"
	keyRingName        = "projects/test-project/locations/us-west1/keyRings/test-key-ring"
	rootName           = keyRingName + "/cryptoKeys/test-root-key"
	rootVersion1       = rootName + "/cryptoKeyVersions/1"
	rootVersion2       = rootName + "/cryptoKeyVersions/2"
	rootVersion3       = rootName + "/cryptoKeyVersions/3"
	signingKeyID       = "test-signing-key"
	signingName        = keyRingName + "/cryptoKeys/" + signingKeyID
	signingVersionName = signingName + "/cryptoKeyVersions/1"
	rotatedName        = signingName + "/cryptoKeyVersions/2"
)

var (
	mu       sync.Once
	now      time.Time
	signer   *nonprod.Signer
	ca       *memca.CertificateAuthority
	rootCert *x509.Certificate
)

func initRoot(t *testing.T) func() {
	return func() {
		now = time.Now()
		ca = memca.Create()
		s, err := testsign.MakeSigner(context.Background(), &testsign.Options{
			Now:               now,
			CA:                ca,
			Root:              testsign.KeyInfo{CommonName: rootCommon, KeyVersionName: rootVersion1},
			PrimarySigningKey: testsign.KeyInfo{CommonName: signingCommon, KeyVersionName: signingVersionName},
			SigningKeys:       []testsign.KeyInfo{{CommonName: rotatedCommon, KeyVersionName: rotatedName}}})
		if err != nil {
			t.Fatalf("MakeSigner failed: %v", err)
		}
		signer = s
		cert, err := sops.GoogleCertificate(context.Background(), &sops.GoogleCertRequest{
			Template: &sops.GoogleCertTemplate{
				Serial:            big.NewInt(1),
				PublicKey:         &signer.Keys[rootVersion1].PublicKey,
				NotBefore:         now,
				SubjectCommonName: rootCommon,
			},
			IssuerKeyVersionName: rootVersion1,
			Random:               testsign.RootRand(),
			Signer:               signer,
		})
		if err != nil {
			t.Fatalf("CreateCertificate for root failed: %v", err)
		}
		rootCert = cert
	}
}

var (
	mockKeyManagement testkms.KeyManagementServer
	mockIam           testkms.IAMPolicyServer
	conn              grpc.ClientConnInterface
)

func TestMain(m *testing.M) {
	conn = testkms.InitGrpcKmsTestServers(
		&testing.T{}, &mockKeyManagement, &mockIam)

	os.Exit(m.Run())
}

func TestFullLocationName(t *testing.T) {
	m := &Manager{Project: "test-project", Location: "neverland"}
	got := m.FullLocationName()
	want := "projects/test-project/locations/neverland"
	if got != want {
		t.Errorf("(&Manager{Project: %q, Location: %q}).FullLocationName() = %q, want %q", "test-project", "neverland", got, want)
	}
}

func TestFullKeyRingName(t *testing.T) {
	m := &Manager{Project: "test-project", Location: "mordor", KeyRingID: "rings-of-power"}
	got := m.FullKeyRingName()
	want := "projects/test-project/locations/mordor/keyRings/rings-of-power"
	if got != want {
		t.Errorf("(&Manager{Project: %q, Location: %q, KeyRingID: %q}).FullKeyRingName() = %q, want %q",
			"test-project", "mordor", "rings-of-power", got, want)
	}
}

func TestFullKeyName(t *testing.T) {
	m := &Manager{Project: "test-project", Location: "mordor", KeyRingID: "rings-of-power"}
	got := m.FullKeyName("key-of-galadriel")
	want := "projects/test-project/locations/mordor/keyRings/rings-of-power/cryptoKeys/key-of-galadriel"
	if got != want {
		t.Errorf("(&Manager{Project: %q, Location: %q, KeyRingID: %q}).FullKeyName(%q) = %q, want %q",
			"test-project", "mordor", "rings-of-power", "key-of-galadriel", got, want)
	}
}

func TestRotateKey(t *testing.T) {
	mu.Do(initRoot(t))

	ctx0 := context.Background()

	// The certificate that rotating will produce
	rotatedSerial := big.NewInt(3)
	rotatedCert, err := sops.GoogleCertificate(ctx0, &sops.GoogleCertRequest{
		Template: &sops.GoogleCertTemplate{
			Serial:            rotatedSerial,
			Issuer:            rootCert,
			PublicKey:         &signer.Keys[rotatedName].PublicKey,
			NotBefore:         now,
			SubjectCommonName: rotatedCommon,
		},
		IssuerKeyVersionName: rootVersion1,
		Random:               testsign.SignerRand(),
		Signer:               signer,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The issuer for signer is root.
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	basicStorage := func(initialObjects map[string][]byte, err error) *storage.Mock {
		if err != nil {
			return storage.WithError(err)
		}
		if initialObjects == nil {
			initialObjects = make(map[string][]byte)
		}
		initialObjects["root.crt"] = rootPEM
		return storage.WithInitialContents(initialObjects, "test")
	}
	ca := &gcsca.CertificateAuthority{
		Storage:             basicStorage(nil, nil),
		PrivateBucket:       "test",
		RootPath:            "root.crt",
		SigningCertDirInGCS: "certs",
	}

	initialManifest := fmt.Sprintf(`entries: {
			key_version_name: "key"
			object_path: "certs/fr1st.crt"
	}
	primary_root_key_version_name: %q
	primary_signing_key_version_name: %q`, rootVersion1, signingVersionName)

	// The order that RPCs transact for rotation is as follows
	//
	const (
		// GetCryptoKey of rotated key - kms [1]
		stepGetKey = iota
		// CABundle for rotated key - storage
		// read manifest - storage
		// CreateCryptoKeyVersion for key - kms [2]
		stepCreateKeyVersion
		// GetPublicKey for new key version - kms [3]
		stepGetNewVersionPK
		// GetPublicKey for root key primary version - kms [4]
		stepGetRootPK
		// AsymmetricSign new key version certificate - kms [5]
		stepSign
		// Write cert to bucket - storage
		// Write updated manifest in bucket - storage
		// DestroyCryptoKeyVersion of old primary key version - kms [7]
		stepDestroyOld
		stepMax
	)

	// The following test cases introduce failures after each successive kms interaction.

	kmsSteps := func(step int, t *testing.T) {
		mockKeyManagement.Clear()
		if step > stepGetKey {
			mockKeyManagement.GetCryptoKeyResp = map[string]*kmspb.CryptoKey{
				rootName: {Name: rootName},
			}
			mockKeyManagement.ListCryptoKeyVersionsResp = map[string]*kmspb.ListCryptoKeyVersionsResponse{
				rootName: {
					CryptoKeyVersions: []*kmspb.CryptoKeyVersion{
						{Name: rotatedName, State: kmspb.CryptoKeyVersion_ENABLED},
					},
				},
			}
		}
		if step > stepCreateKeyVersion {
			mockKeyManagement.CreateCryptoKeyVersionResp = map[string]*kmspb.CryptoKeyVersion{
				signingName: {
					Name:  rotatedName,
					State: kmspb.CryptoKeyVersion_ENABLED,
				},
			}
		}
		if step > stepGetNewVersionPK {
			mockKeyManagement.AddPKResponse(rotatedName, signer, t)
		}
		if step > stepGetRootPK {
			mockKeyManagement.AddPKResponse(rootVersion1, signer, t)
		}
		if step > stepSign {
			mockKeyManagement.AddKmsSignatureResponse(rotatedCert.RawTBSCertificate, rotatedCert.Signature)
		}
		if step > stepDestroyOld {
			mockKeyManagement.DestroyCryptoKeyVersionResp = map[string]*kmspb.CryptoKeyVersion{
				signingVersionName: {Name: signingVersionName,
					DestroyTime: &timestamppb.Timestamp{Seconds: 420},
				},
			}
			mockKeyManagement.GetCryptoKeyVersionResp = map[string]*kmspb.CryptoKeyVersion{
				rotatedName: {
					Name:  rotatedName,
					State: kmspb.CryptoKeyVersion_ENABLED,
				},
			}
		}
	}
	tests := []struct {
		name                  string
		common                string
		keyID                 string
		setupKms              func(t *testing.T)
		wantErr               string
		want                  string
		wantCerts             map[string][]byte // keyVersionName -> raw cert
		wantPrimarySigningKey string            // Manifest field.
		storageErr            error
	}{
		{
			name:     "happy path",
			common:   rotatedCommon,
			keyID:    signingKeyID, // Not a key version, but the key to rotate.
			setupKms: func(t *testing.T) { kmsSteps(stepMax, t) },
			want:     rotatedName,
			wantCerts: map[string][]byte{
				rotatedName: rotatedCert.Raw,
			},
			wantPrimarySigningKey: rotatedName,
		},
		{
			name:     "nonexistent key",
			common:   rotatedCommon,
			keyID:    "dne",
			setupKms: func(t *testing.T) { kmsSteps(stepGetKey, t) },
			wantErr:  "error creating new key version for \"projects/test-project/locations/us-west1/keyRings/test-key-ring/cryptoKeys/dne\"",
		},
		{
			name:     "create key failed",
			common:   rotatedCommon,
			keyID:    signingKeyID,
			setupKms: func(t *testing.T) { kmsSteps(stepCreateKeyVersion, t) },
			wantErr:  fmt.Sprintf("error creating new key version for %q:", signingName),
		},
		{
			name:     "can't get new key version pk",
			setupKms: func(t *testing.T) { kmsSteps(stepGetNewVersionPK, t) },
			keyID:    signingKeyID,
			common:   rotatedCommon,
			wantErr:  fmt.Sprintf("could not get public key for key version %q", rotatedName),
		},
		{
			name:     "can't get root pk during CreateCertificate",
			setupKms: func(t *testing.T) { kmsSteps(stepGetRootPK, t) },
			keyID:    signingKeyID,
			common:   rotatedCommon,
			wantErr:  "could not create certificate",
		},
		{
			name:     "signing fails",
			setupKms: func(t *testing.T) { kmsSteps(stepSign, t) },
			keyID:    signingKeyID,
			common:   rotatedCommon,
			wantErr:  "could not create certificate",
		},
		{
			name:       "manifest permission error during finalization",
			setupKms:   func(t *testing.T) { kmsSteps(stepDestroyOld, t) },
			keyID:      signingKeyID,
			common:     rotatedCommon,
			storageErr: errors.New("permission denied"),
			wantErr:    "permission denied",
		},
	}
	keyClient := kmspb.NewKeyManagementServiceClient(conn)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// create a fresh storage server for each test case.
			ca.Storage = basicStorage(map[string][]byte{
				gcsca.ManifestObjectName: []byte(initialManifest)}, tc.storageErr)

			m := &Manager{
				Project:   "test-project",
				Location:  "us-west1",
				KeyRingID: "test-key-ring",
				KeyClient: keyClient,
				IAMClient: iampb.NewIAMPolicyClient(conn),
			}
			ctx1 := keys.NewContext(ctx0, &keys.Context{
				CA:      ca,
				Signer:  &Signer{Manager: m},
				Random:  testsign.SignerRand(),
				Manager: m,
			})
			ctx2 := NewSigningKeyContext(ctx1, &SigningKeyContext{
				SigningKeyID: tc.keyID,
			})
			mockKeyManagement.Clear()
			if tc.setupKms != nil {
				tc.setupKms(t)
			}
			ctx := rotate.NewSigningKeyContext(ctx2, &rotate.SigningKeyContext{
				SigningKeyCommonName: tc.common,
				SigningKeySerial:     rotatedSerial,
				Now:                  now,
			})
			got, err := rotate.Key(ctx)
			if !match.Error(err, tc.wantErr) {
				t.Fatalf("Key(_, _, %q) = %v, want %q", tc.keyID, err, tc.wantErr)
			}
			if tc.wantErr == "" {
				if got != tc.want {
					t.Errorf("Key({...%q...}) = %v, want %v", tc.keyID, got, tc.want)
				}
				for keyVersionName, contents := range tc.wantCerts {
					got, err := ca.Certificate(ctx, keyVersionName)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, contents) {
						t.Errorf("ca.Certificate(_, %q) = %v, want %v", keyVersionName, got, contents)
					}
				}
			}
		})
	}
}
