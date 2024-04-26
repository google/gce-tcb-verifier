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
	"crypto/x509"
	"encoding/hex"
	"fmt"

	cpb "github.com/google/gce-tcb-verifier/proto/certificates"
	styp "github.com/google/gce-tcb-verifier/sign/types"
	"google.golang.org/protobuf/encoding/prototext"
)

// MockSigner implements the CertificateAuthority and Signer interfaces to parrot back results.
type MockSigner struct {
	Certificates map[string][]byte
	CABundles    map[string][]byte
	// Signatures maps a key name to a map of hex-encoded toSign bytes to its signature bytes
	Signatures        map[string]map[string][]byte
	PublicKeys        map[string][]byte
	RootKeyVersion    string
	SigningKeyVersion string
	PrepareErr        error
}

// Certificate returns the certificate of the given keyVersionName.
func (m *MockSigner) Certificate(_ context.Context, keyVersionName string) ([]byte, error) {
	bytes, ok := m.Certificates[keyVersionName]
	if !ok {
		return nil, fmt.Errorf("missing certificate for key %q", keyVersionName)
	}
	return bytes, nil
}

// CABundle returns the CA chain of certificates for certifying the given key's certificate.
func (m *MockSigner) CABundle(_ context.Context, keyName string) ([]byte, error) {
	bytes, ok := m.CABundles[keyName]
	if !ok {
		return nil, fmt.Errorf("missing CA bundle for key %q", keyName)
	}
	return bytes, nil
}

// Sign signs the given data with the named key version.
func (m *MockSigner) Sign(_ context.Context, keyVersionName string, toSign []byte) ([]byte, error) {
	signatureMap, ok := m.Signatures[keyVersionName]
	if !ok {
		return nil, fmt.Errorf("missing signature map for key %q", keyVersionName)
	}
	bytes, ok := signatureMap[hex.EncodeToString(toSign)]
	if !ok {
		return nil, fmt.Errorf("missing %q's signature for message %v", keyVersionName, toSign)
	}
	return bytes, nil
}

// PublicKey returns the PEM encoded public key for the named key.
func (m *MockSigner) PublicKey(_ context.Context, keyVersionName string) ([]byte, error) {
	bytes, ok := m.PublicKeys[keyVersionName]
	if !ok {
		return nil, fmt.Errorf("missing public key for %q", keyVersionName)
	}
	return bytes, nil
}

// PrimaryRootKeyVersion returns the keyVersionName of the active root key.
func (m *MockSigner) PrimaryRootKeyVersion(_ context.Context) (string, error) {
	return m.RootKeyVersion, nil
}

// PrimarySigningKeyVersion returns the keyVersionName of the active signing key.
func (m *MockSigner) PrimarySigningKeyVersion(_ context.Context) (string, error) {
	return m.SigningKeyVersion, nil
}

// PrepareResources ensures all necessary resources are present for the CA to function. This is
// needed for bootstrapping.
func (m *MockSigner) PrepareResources(context.Context) error { return m.PrepareErr }

// FakeMutation manages changes to the MockSigner through the CertificateAuthorityMutation
// interface.
type FakeMutation struct {
	Root     string
	Signer   string
	RootCert *x509.Certificate
	Certs    map[string]*x509.Certificate
}

// SetPrimaryRootKeyVersion updates the mutation object to change the primary root key
// version to the given one.
func (m *FakeMutation) SetPrimaryRootKeyVersion(keyVersionName string) {
	m.Root = keyVersionName
}

// SetPrimarySigningKeyVersion updates the mutation object to change the primary signing key
// version to the given one.
func (m *FakeMutation) SetPrimarySigningKeyVersion(keyVersionName string) {
	m.Signer = keyVersionName
}

// AddSigningKeyCert adds a certificate for the given keyVersionName to the CA.
func (m *FakeMutation) AddSigningKeyCert(keyVersionName string, cert *x509.Certificate) {
	if m.Certs == nil {
		m.Certs = make(map[string]*x509.Certificate)
	}
	m.Certs[keyVersionName] = cert
}

// SetRootKeyCert changes the CA's stored root certificate to cert.
func (m *FakeMutation) SetRootKeyCert(cert *x509.Certificate) {
	m.RootCert = cert
}

// NewMutation returns an object that manages changes to the CA's persistent state.
func (m *MockSigner) NewMutation() styp.CertificateAuthorityMutation {
	return &FakeMutation{}
}

// Finalize completes any unflushed changes that the given mutation represents. The mutation
// object should be the same type as NewMutation returns.
func (m *MockSigner) Finalize(_ context.Context, mutation styp.CertificateAuthorityMutation) error {
	mut, ok := mutation.(*FakeMutation)
	if !ok {
		return fmt.Errorf("expected testlib.CertificateAuthorityMutation, got %v", mutation)
	}
	m.RootKeyVersion = mut.Root
	m.SigningKeyVersion = mut.Signer

	if m.Certificates == nil {
		m.Certificates = make(map[string][]byte)
	}
	for k, cert := range mut.Certs {
		m.Certificates[k] = cert.Raw
	}
	return nil
}

// Wipeout removes all certificates and keys from the mock.
func (m *MockSigner) Wipeout(context.Context) error {
	m.CABundles = make(map[string][]byte)
	m.Certificates = make(map[string][]byte)
	m.PublicKeys = make(map[string][]byte)
	m.Signatures = make(map[string]map[string][]byte)
	return nil
}

// ExtendManifest creates a textproto based on an initial textproto with extensions to the entries
// and a possible modification to the primary signing key version name.
func ExtendManifest(initial, key, path, primarySigningKey string) []byte {
	manifest := &cpb.GCECertificateManifest{}
	if err := prototext.Unmarshal([]byte(initial), manifest); err != nil {
		panic(err)
	}
	newEntry := &cpb.GCECertificateManifest_Entry{
		KeyVersionName: key,
		ObjectPath:     path,
	}
	manifest.Entries = append(manifest.Entries, newEntry)
	if primarySigningKey != "" {
		manifest.PrimarySigningKeyVersionName = primarySigningKey
	}
	out, err := prototext.Marshal(manifest)
	if err != nil {
		panic(err)
	}
	return out
}
