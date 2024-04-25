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
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	styp "github.com/google/gce-tcb-verifier/sign/types"
)

// VerifyChain returns whether the certificate for keyName is verified by the CABundle.
func VerifyChain(ctx context.Context, ca styp.CertificateAuthority, keyVersionName string, now time.Time) error {
	signingKeyCert, err := CertificateX509(ctx, ca, keyVersionName)
	if err != nil {
		return err
	}
	trust, err := CertPool(ctx, ca, keyVersionName)
	if err != nil {
		return err
	}

	if _, err := signingKeyCert.Verify(x509.VerifyOptions{
		Roots: trust,
		// No intermediates in this signing chain.
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return err
	}
	return nil
}

// VerifySignatureFromCA verifies a message's signature from keyName as it is rooted from the given
// certificate authority.
func VerifySignatureFromCA(ctx context.Context, ca styp.CertificateAuthority, keyVersionName string, now time.Time, message, signature []byte) error {
	if err := VerifyChain(ctx, ca, keyVersionName, now); err != nil {
		return err
	}
	signerCert, err := CertificateX509(ctx, ca, keyVersionName)
	if err != nil {
		return err
	}
	return VerifySignature(ctx, signerCert, message, signature)
}

// checkSignerCertificate returns whether the given signingKeyCert has the expected parameters, and
// the RSA public key if it does.
func checkSigningKeyCertificate(signingKeyCert *x509.Certificate) (*rsa.PublicKey, error) {
	if signingKeyCert.SignatureAlgorithm != x509.SHA256WithRSAPSS {
		return nil, fmt.Errorf("signingKeyCert signatureAlgorithm is %v, expect SHA256 with RSAPSS", signingKeyCert.SignatureAlgorithm)
	}
	if signingKeyCert.PublicKeyAlgorithm != x509.RSA {
		return nil, fmt.Errorf("signingKeyCert publicKeyAlgorithm is %v, expect RSA", signingKeyCert.PublicKeyAlgorithm)
	}
	pub, ok := signingKeyCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("signingKeyCert must be for an RSA public key")
	}
	return pub, nil
}

// VerifySignature returns whether the given signingKeyCert verifies a message's signature.
func VerifySignature(_ context.Context, signingKeyCert *x509.Certificate, message, signature []byte) error {
	pub, err := checkSigningKeyCertificate(signingKeyCert)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(message)
	return rsa.VerifyPSS(pub, crypto.SHA256, digest[:], signature,
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		})
}
