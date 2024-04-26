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
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/google/gce-tcb-verifier/cmd/output"
	"github.com/google/gce-tcb-verifier/keys"
	styp "github.com/google/gce-tcb-verifier/sign/types"
)

// The modern version for x.509 is 3.
const x509v3Version = 3

func googleName(common, serial string) pkix.Name {
	return pkix.Name{
		Country:            []string{"USA"},
		Organization:       []string{"Google"},
		OrganizationalUnit: []string{"Engineering"},
		Locality:           []string{"Kirkland"},
		Province:           []string{"WA"},
		CommonName:         common,
		SerialNumber:       serial,
	}
}

// GoogleCertTemplate represents the configurable components of an x.509 certificate issued for
// the purposes of confidential computing TCB endorsement.
type GoogleCertTemplate struct {
	// Serial is both the subject serial number and the cert serial number, since we don't recertify
	// the same key and don't want to track cert serial numbers.
	Serial            *big.Int
	PublicKey         any
	Issuer            *x509.Certificate
	NotBefore         time.Time
	SubjectCommonName string
}

// GoogleCertificateTemplate returns a Google Cloud Kirkland Engineering certificate template for use
// in the GCE TCB signing key chain.
func GoogleCertificateTemplate(tmpl *GoogleCertTemplate) (*x509.Certificate, error) {
	var issuer pkix.Name
	subject := googleName(tmpl.SubjectCommonName, tmpl.Serial.String())
	if tmpl.Issuer == nil {
		issuer = subject
	} else {
		issuer = tmpl.Issuer.Subject
	}
	template := &x509.Certificate{
		// The certificate serial number is the same as the subject's since we don't reissue
		// certificates.
		SerialNumber:          tmpl.Serial,
		Issuer:                issuer,
		Subject:               subject,
		SignatureAlgorithm:    x509.SHA256WithRSAPSS,
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             tmpl.PublicKey,
		Version:               x509v3Version,
		BasicConstraintsValid: true,
		NotBefore:             tmpl.NotBefore,
	}
	if tmpl.Issuer == nil {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.MaxPathLenZero = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.NotAfter = tmpl.NotBefore.Add(time.Duration(styp.RootValidDays) * 24 * time.Hour)
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.NotAfter = tmpl.NotBefore.Add(time.Duration(styp.SignValidDays) * 24 * time.Hour)
	}
	return template, nil
}

// cryptoSigner implements the crypto.Signer interface for x509.CreateCertificate.
type cryptoSigner struct {
	ctx            context.Context
	keyVersionName string
	signer         styp.Signer
}

func (s *cryptoSigner) Public() crypto.PublicKey {
	key, err := RsaPublicKey(s.ctx, s.signer, s.keyVersionName)
	if err != nil {
		output.Errorf(s.ctx, "could not get public key for %q: %v", s.keyVersionName, err)
		return nil
	}
	return key
}

func (s *cryptoSigner) Sign(_ io.Reader, digest []byte, signerOpts crypto.SignerOpts) ([]byte, error) {
	// crypto/x509's CreateCertificate will always provide the expected PSS w/SHA256 options given
	// the SignatureAlgorithm in the template certificate, so we don't need to double-check it here.
	// The nested signer should check that its opts match the algorithm it chooses.
	return s.signer.Sign(s.ctx, s.keyVersionName, styp.Digest{SHA256: digest}, signerOpts)
}

// CertRequest represents the required components to mint a certificate from a template, provided
// the context contains a keys.Context.
type CertRequest struct {
	Issuer               *x509.Certificate
	Template             *x509.Certificate
	IssuerKeyVersionName string
	Signer               styp.Signer
	Random               io.Reader
}

// CreateCertificateFromTemplate returns a signed certificate of the given template by the key
// described by parent. The issuer's private key is keyVersionName, to be given to the given Signer
// instance.
func CreateCertificateFromTemplate(ctx context.Context, req *CertRequest) (*x509.Certificate, error) {
	trueParent := req.Issuer
	if req.Issuer == nil {
		trueParent = req.Template
	}
	bytes, err := x509.CreateCertificate(req.Random, req.Template, trueParent, req.Template.PublicKey,
		&cryptoSigner{ctx: ctx, keyVersionName: req.IssuerKeyVersionName, signer: req.Signer})
	if err != nil {
		return nil, fmt.Errorf("could not create certificate: %v", err)
	}
	return x509.ParseCertificate(bytes)
}

// GoogleCertRequest represents a request to sign a Google certificate template.
type GoogleCertRequest struct {
	Template             *GoogleCertTemplate
	IssuerKeyVersionName string
	Signer               styp.Signer
	Random               io.Reader
}

// GoogleCertificate returns a signed Google-templated certificate with the given serial
// number for the subject. The certificate's serial number is also set to the subject's serial
// number, since certificates are not reissued.
func GoogleCertificate(ctx context.Context, req *GoogleCertRequest) (*x509.Certificate, error) {
	rotatedTemplate, err := GoogleCertificateTemplate(req.Template)
	if err != nil {
		return nil, err
	}
	return CreateCertificateFromTemplate(ctx, &CertRequest{
		Issuer:               req.Template.Issuer,
		Template:             rotatedTemplate,
		IssuerKeyVersionName: req.IssuerKeyVersionName,
		Signer:               req.Signer,
		Random:               req.Random,
	})
}

// NextSigningKeySerial returns the current signing key's certificate subject serial number
// plus one.
func NextSigningKeySerial(ctx context.Context) (*big.Int, error) {
	// No override, default to previous primary signing key's serial number + 1.
	kctx, err := keys.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	signingKeyVersion, err := kctx.CA.PrimarySigningKeyVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not get primary signing key version: %v", err)
	}
	certBytes, err := kctx.CA.Certificate(ctx, signingKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("could not get current primary signing key (%s) certificate: %v",
			signingKeyVersion, err)
	}
	signingKeyCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse primary signing key certificate: %v", err)
	}
	// The certificate serial number is not necessarily the subject's serial number, so we parse
	// that into a big.Int
	z, ok := new(big.Int).SetString(signingKeyCert.Subject.SerialNumber, 0)
	if !ok {
		return nil, fmt.Errorf("could not parse current signing key's subject key serial number %q",
			signingKeyCert.Subject.SerialNumber)
	}
	return z.Add(z, big.NewInt(1)), nil
}
