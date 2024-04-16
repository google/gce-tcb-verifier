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

package ops

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"golang.org/x/net/context"

	"github.com/google/gce-tcb-verifier/sign/transform"
	styp "github.com/google/gce-tcb-verifier/sign/types"
)

// CertPool returns the Signer's CABundle as an x509.CertPool.
func CertPool(ctx context.Context, ca styp.CertificateAuthority, keyVersionName string) (*x509.CertPool, error) {
	pems, err := ca.CABundle(ctx, keyVersionName)
	if err != nil {
		return nil, err
	}
	trust := x509.NewCertPool()
	if !trust.AppendCertsFromPEM(pems) {
		return nil, fmt.Errorf("parse error when decoding CA bundle for %q", keyVersionName)
	}
	return trust, nil
}

// CertificateX509 returns the Signer's certificate as an x509.Certificate.
func CertificateX509(ctx context.Context, ca styp.CertificateAuthority, keyVersionName string) (*x509.Certificate, error) {
	signingKeyCertBytes, err := ca.Certificate(ctx, keyVersionName)
	if err != nil {
		return nil, fmt.Errorf("could not fetch certificate for key %q: %w", keyVersionName, err)
	}
	cert, err := x509.ParseCertificate(signingKeyCertBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate for %q: %w", keyVersionName, err)
	}
	return cert, nil
}

// RsaPublicKey returns s.PublicKey interpreted into an rsa.PublicKey
func RsaPublicKey(ctx context.Context, s styp.Signer, keyVersionName string) (*rsa.PublicKey, error) {
	if s == nil {
		return nil, fmt.Errorf("signer is nil")
	}
	signingKeyPEM, err := s.PublicKey(ctx, keyVersionName)
	if err != nil {
		return nil, err
	}
	key, err := transform.DecodePEMRsaKey(signingKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("could not decode public key for %s: %v", keyVersionName, err)
	}
	return key, nil
}

// IssuerCertFromBundle uses the provided certificate authority instance to parse out the given
// keyVersionName's issuer certificate.
func IssuerCertFromBundle(ctx context.Context, ca styp.CertificateAuthority, keyVersionName string) (*x509.Certificate, error) {
	pemBytes, err := ca.CABundle(ctx, keyVersionName)
	if err != nil {
		return nil, fmt.Errorf("could not fetch CA bundle: %v", err)
	}
	return transform.PemToCertificate(pemBytes)
}
