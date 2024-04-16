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

// Package transform provides decoding utilities for certificate formats.
package transform

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
)

// PemToCertificate returns a parsed "CERTIFICATE" PEM-encoded x509 certificate or an error.
func PemToCertificate(pemBytes []byte) (*x509.Certificate, error) {
	certBlock, rest := pem.Decode(pemBytes)
	if certBlock == nil {
		return nil, fmt.Errorf("could not decode PEM certificate(s)")
	}
	if certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("the CA bundle does not contain a certificate. Got %s", certBlock.Type)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("expected a single certificate in the CA bundle. Got %d trailing bytes", len(rest))
	}
	issuer, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse issuer certificate: %v", err)
	}
	return issuer, nil
}

// DecodePEMRsaKey returns the given PEM-encoded bytes as an rsa.PublicKey or an error.
func DecodePEMRsaKey(keyPEM []byte) (*rsa.PublicKey, error) {
	block, rest := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("signer returned a non-PEM public key: %v", keyPEM)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("public key PEM block has non-zero remainder")
	}

	wantType := "PUBLIC KEY"
	switch block.Type {
	case "RSA PUBLIC KEY":
		var pub struct {
			N []byte
			E int
		}
		if rest, err := asn1.Unmarshal(block.Bytes, &pub); err != nil || len(rest) != 0 {
			return nil, fmt.Errorf("could not unmarshal public key DER: %v", err)
		}
		N := new(big.Int)
		N.SetBytes(pub.N)
		return &rsa.PublicKey{N: N, E: pub.E}, nil
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse public key DER: %v", err)
		}
		rsaPK, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("got PK %v, want an RSA key", pub)
		}
		return rsaPK, nil
	default:
		return nil, fmt.Errorf("keyPEM public key has PEM block type %q, expect %q", block.Type, wantType)
	}
}
