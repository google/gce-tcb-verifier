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

// Package certs provides certificate templating logic for nonprod key management.
package certs

import (
	"context"
	"crypto/x509"
	"math/big"
	"time"

	"github.com/google/gce-tcb-verifier/rotate"
	styp "github.com/google/gce-tcb-verifier/sign/types"
)

// SigningKeyContextFrom returns signer key certificate information from the context whether it's
// from BootstrapContext or SigningKeyContext.
func SigningKeyContextFrom(ctx context.Context) (*rotate.SigningKeyContext, error) {
	if bc, err := rotate.FromBootstrapContext(ctx); err == nil {
		return &rotate.SigningKeyContext{
			Now:                  bc.Now,
			SigningKeyCommonName: bc.SigningKeyCommonName,
			SigningKeySerial:     bc.SigningKeySerial,
		}, nil
	}
	return rotate.FromSigningKeyContext(ctx)
}

// TemplateFromCert provides a certificate template based on a given template and the provided
// configurables.
func TemplateFromCert(ctx context.Context, cert *x509.Certificate, pubKey any) (*x509.Certificate, error) {
	var subjectCn string
	var subjectSerial *big.Int
	var timestamp time.Time

	template := *cert // copy the root certificate
	template.PublicKey = pubKey
	// The raw material must be cleared since it's invalid for the new values.
	template.Raw = nil
	template.RawTBSCertificate = nil
	template.RawSubjectPublicKeyInfo = nil
	template.RawSubject = nil
	template.RawIssuer = nil

	if cert.IsCA {
		bc, err := rotate.FromBootstrapContext(ctx)
		if err != nil {
			return nil, err
		}
		subjectCn = bc.RootKeyCommonName
		subjectSerial = bc.RootKeySerial
		timestamp = bc.Now
		template.Issuer.CommonName = bc.RootKeyCommonName
		template.Issuer.SerialNumber = subjectSerial.String()
	} else {
		skc, err := SigningKeyContextFrom(ctx)
		if err != nil {
			return nil, err
		}
		subjectCn = skc.SigningKeyCommonName
		subjectSerial = skc.SigningKeySerial
		timestamp = skc.Now
	}

	template.Subject.CommonName = subjectCn
	template.Subject.SerialNumber = subjectSerial.String()
	template.NotBefore = timestamp
	template.NotAfter = timestamp.Add(time.Duration(styp.SignValidDays) * 24 * time.Hour)
	return &template, nil
}
