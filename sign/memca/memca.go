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

// Package memca provides the CertificateAuthority interface entirely in memory without persistence.
package memca

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/google/gce-tcb-verifier/keys"
	"github.com/google/gce-tcb-verifier/sign/transform"
	styp "github.com/google/gce-tcb-verifier/sign/types"
	"github.com/google/gce-tcb-verifier/testing/devkeys"
	"github.com/spf13/cobra"
)

// CertificateAuthority implements the certificate authority interface, and can be used as both a
// mock and a fake given that its internal respresentation is exported.
type CertificateAuthority struct {
	Certs map[string]*x509.Certificate

	RootName          string
	PrimarySigningKey string
}

// Create returns a new CertificateAuthority object that's ready for use.
func Create() *CertificateAuthority {
	return &CertificateAuthority{Certs: make(map[string]*x509.Certificate)}
}

func (ca *CertificateAuthority) getCert(name string) (*x509.Certificate, bool) {
	if ca.Certs == nil {
		return nil, false
	}
	cert, ok := ca.Certs[name]
	return cert, ok
}

func (ca *CertificateAuthority) setCert(name string, cert *x509.Certificate) {
	if ca.Certs == nil {
		ca.Certs = make(map[string]*x509.Certificate)
	}
	ca.Certs[name] = cert
}

// Certificate returns the DER-encoded certificate of the given keyVersionName.
func (ca *CertificateAuthority) Certificate(_ context.Context, keyVersionName string) ([]byte, error) {
	keyCert, ok := ca.getCert(keyVersionName)
	if !ok {
		return nil, fmt.Errorf("invalid key: %s", keyVersionName)
	}
	return keyCert.Raw, nil
}

// CABundle returns the PEM-encoded certificate chain for inner intermediates to root for the
// CertificateAuthority key of the given keyName.
func (ca *CertificateAuthority) CABundle(context.Context, string) ([]byte, error) {
	rootCert, ok := ca.getCert(ca.RootName)
	if !ok {
		return nil, fmt.Errorf("root %q does not have a certificate", ca.RootName)
	}

	result := pem.EncodeToMemory(&pem.Block{Bytes: rootCert.Raw, Type: "CERTIFICATE"})
	return result, nil
}

// PrimaryRootKeyVersion returns the keyVersionName of the active root key.
func (ca *CertificateAuthority) PrimaryRootKeyVersion(context.Context) (string, error) {
	return ca.RootName, nil
}

// PrimarySigningKeyVersion returns the keyVersionName of the active signing key.
func (ca *CertificateAuthority) PrimarySigningKeyVersion(context.Context) (string, error) {
	return ca.PrimarySigningKey, nil
}

// Finalize completes any unflushed changes that the given mutation represents. The mutation
// object should be the same type as NewMutation returns.
func (ca *CertificateAuthority) Finalize(context.Context, styp.CertificateAuthorityMutation) error {
	return nil
}

// NewMutation returns an object that manages changes to the CA's persistent state.
func (ca *CertificateAuthority) NewMutation() styp.CertificateAuthorityMutation {
	return &Mutation{ca: ca}
}

// Mutation represents a memca.CertificateAuthority mutation.
type Mutation struct {
	ca *CertificateAuthority
}

// SetPrimaryRootKeyVersion updates the mutation object to change the primary root key
// version to the given one.
func (m *Mutation) SetPrimaryRootKeyVersion(keyVersionName string) { m.ca.RootName = keyVersionName }

// SetPrimarySigningKeyVersion updates the mutation object to change the primary signing key
// version to the given one.
func (m *Mutation) SetPrimarySigningKeyVersion(keyVersionName string) {
	m.ca.PrimarySigningKey = keyVersionName
}

// AddSigningKeyCert adds a certificate for the given keyVersionName to the CA.
func (m *Mutation) AddSigningKeyCert(keyVersionName string, cert *x509.Certificate) {
	m.ca.setCert(keyVersionName, cert)
}

// SetRootKeyCert changes the CA's stored root certificate to cert.
func (m *Mutation) SetRootKeyCert(cert *x509.Certificate) {
	m.ca.setCert(m.ca.RootName, cert)
}

// PrepareResources ensures all necessary resources are present for the CA to function. This is
// needed for bootstrapping.
func (ca *CertificateAuthority) PrepareResources(context.Context) error { return nil }

// Wipeout destroys all persisted resources for the CA.
func (ca *CertificateAuthority) Wipeout(context.Context) error {
	ca.Certs = make(map[string]*x509.Certificate)
	ca.RootName = ""
	ca.PrimarySigningKey = ""
	return nil
}

// memca implements CommandComponent to compose well in the CLI construction.

// InitContext extends the given context with whatever else the component needs before execution.
func (ca *CertificateAuthority) InitContext(ctx context.Context) (context.Context, error) {
	c, err := keys.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	c.CA = ca
	return ctx, nil
}

// AddFlags adds any implementation-specific flags for this command component.
func (ca *CertificateAuthority) AddFlags(*cobra.Command) {}

// PersistentPreRunE returns an error if the results of the parsed flags constitute an error.
func (ca *CertificateAuthority) PersistentPreRunE(*cobra.Command, []string) error {
	return nil
}

// TestOnlyCertificateAuthority returns a CertificateAuthority object that can be used for testing
// based on pre-generated development keys.
func TestOnlyCertificateAuthority() *CertificateAuthority {
	ca := Create()
	rc, _ := transform.PemToCertificate(devkeys.RootCert)
	pc, _ := x509.ParseCertificate(devkeys.PrimarySigningKeyCert)
	mut := ca.NewMutation()
	mut.SetPrimaryRootKeyVersion("root")
	mut.SetPrimarySigningKeyVersion("primarySigningKey")
	mut.SetRootKeyCert(rc)
	mut.AddSigningKeyCert("primarySigningKey", pc)
	err := ca.Finalize(context.Background(), mut)
	if err != nil {
		panic(err)
	}
	return ca
}
