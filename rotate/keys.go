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

package rotate

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/gce-tcb-verifier/keys"
	sops "github.com/google/gce-tcb-verifier/sign/ops"
	styp "github.com/google/gce-tcb-verifier/sign/types"
)

var (
	// ErrNoSigningKeySerial is returned during certificate template construction when the signing
	// key serial number is undetermined.
	ErrNoSigningKeySerial = errors.New("could not determine signing key serial number")
)

// InternalSignAndUploadRequest is exported for internal testing.
type InternalSignAndUploadRequest struct {
	Mutation              styp.CertificateAuthorityMutation
	Issuer                *x509.Certificate
	SubjectKeyVersionName string
	IssuerKeyVersionName  string
}

func signCert(ctx context.Context, req *InternalSignAndUploadRequest) (*x509.Certificate, error) {
	c, err := keys.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	subjectPubKey, err := sops.RsaPublicKey(ctx, c.Signer, req.SubjectKeyVersionName)
	if err != nil {
		return nil, fmt.Errorf("could not get public key for key version %q: %v", req.SubjectKeyVersionName, err)
	}
	template, err := c.Manager.CertificateTemplate(ctx, req.Issuer, subjectPubKey)
	if err != nil {
		return nil, err
	}

	cert, err := sops.CreateCertificateFromTemplate(ctx, &sops.CertRequest{
		Issuer:               req.Issuer,
		Template:             template,
		IssuerKeyVersionName: req.IssuerKeyVersionName,
		Signer:               c.Signer,
		Random:               c.Random,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create certificate for key version %q: %v", req.SubjectKeyVersionName, err)
	}

	req.Mutation.AddSigningKeyCert(req.SubjectKeyVersionName, cert)
	return cert, nil
}

// InternalSignAndUpload should only be used internally for testing implementations.
func InternalSignAndUpload(ctx context.Context, req *InternalSignAndUploadRequest) (*x509.Certificate, error) {
	cert, err := signCert(ctx, req)
	if err != nil {
		return nil, err
	}
	if req.Issuer == nil {
		req.Mutation.SetRootKeyCert(cert)
	} else {
		req.Mutation.AddSigningKeyCert(req.SubjectKeyVersionName, cert)
	}
	return cert, nil
}

// GoogleCertificateTemplate returns a certificate template with metadata indicating a Google
// source, specifically the Confidential Computing engineering team in Kirkland, WA, USA.
func GoogleCertificateTemplate(ctx context.Context, issuer *x509.Certificate, subjectPubKey any) (*x509.Certificate, error) {
	bc, err := FromBootstrapContext(ctx)
	var now time.Time
	var commonName string
	var serial *big.Int
	// Root keys need a bootstrap context.
	if err != nil {
		if issuer == nil {
			return nil, err
		}
		// Bootstrap and rotate contexts should not co-exist, so only checking in this case is fine.
		skc, err := FromSigningKeyContext(ctx)
		if err != nil {
			return nil, err
		}
		commonName = skc.SigningKeyCommonName
		serial = skc.SigningKeySerial
		now = skc.Now
	} else {
		now = bc.Now
		if issuer == nil {
			commonName = bc.RootKeyCommonName
			serial = bc.RootKeySerial
		} else {
			commonName = bc.SigningKeyCommonName
			serial = bc.SigningKeySerial
		}
	}
	if serial == nil {
		return nil, ErrNoSigningKeySerial
	}
	return sops.GoogleCertificateTemplate(&sops.GoogleCertTemplate{
		Serial:            serial,
		PublicKey:         subjectPubKey,
		Issuer:            issuer,
		NotBefore:         now,
		SubjectCommonName: commonName,
	})
}
