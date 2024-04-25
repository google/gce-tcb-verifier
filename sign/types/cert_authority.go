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

package types

import (
	"context"
	"crypto/x509"
)

const (
	// SignValidDays is our firmware support lifetime. We choose 5 years to follow similar guidelines
	// as for TPM endorsement key certificates, which are typically 5-10 years:
	// https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
	SignValidDays = int(5*365 + 1)
	// RootValidDays is same duration as the AMD SEV-SNP root key: 25 years.
	RootValidDays = int(25 * 365.24)
	// KeyBitLength is the expected key size for RSA keys used for UEFI signing.
	KeyBitLength = 4096
	// RootCommonName is the GCE confidential computing TCB root key certificate's common name.
	RootCommonName = "GCE-cc-tcb-root"
	// UEFISigningCommonName is the GCE UEFI signer signing key certificate's common name.
	UEFISigningCommonName = "GCE-uefi-signing-key"
)

// Our certificate authority is offline. Certificates are stored on Colossus.

// CertificateAuthority is an interface for retrieving the certificates for named keys.
type CertificateAuthority interface {
	// Certificate returns the certificate for the named key version in DER format.
	Certificate(ctx context.Context, keyVersionName string) ([]byte, error)
	// CABundle returns the intermediate..root certificate chain as consecutive PEM blocks for the
	// named key version.
	CABundle(ctx context.Context, keyVersionName string) ([]byte, error)
	// PrimaryRootKeyVersion returns the keyVersionName of the active root key.
	PrimaryRootKeyVersion(ctx context.Context) (string, error)
	// PrimarySigningKeyVersion returns the keyVersionName of the active signing key.
	PrimarySigningKeyVersion(ctx context.Context) (string, error)
	// NewMutation returns an object that manages changes to the CA's persistent state.
	NewMutation() CertificateAuthorityMutation
	// Finalize completes any unflushed changes that the given mutation represents. The mutation
	// object should be the same type as NewMutation returns.
	Finalize(ctx context.Context, mutation CertificateAuthorityMutation) error
	// PrepareResources ensures all necessary resources are present for the CA to function. This is
	// needed for bootstrapping.
	PrepareResources(ctx context.Context) error
	// Wipeout destroys all persisted resources for the CA.
	Wipeout(ctx context.Context) error
}

// CertificateAuthorityMutation represents a change to the current state of the CA.
type CertificateAuthorityMutation interface {
	// SetPrimaryRootKeyVersion updates the mutation object to change the primary root key
	// version to the given one.
	SetPrimaryRootKeyVersion(keyVersionName string)
	// SetPrimarySigningKeyVersion updates the mutation object to change the primary signing key
	// version to the given one.
	SetPrimarySigningKeyVersion(keyVersionName string)
	// AddSigningKeyCert adds a certificate for the given keyVersionName to the CA.
	AddSigningKeyCert(keyVersionName string, cert *x509.Certificate)
	// SetRootKeyCert changes the CA's stored root certificate to cert.
	SetRootKeyCert(cert *x509.Certificate)
}
