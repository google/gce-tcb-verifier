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

// Package nonprod provides an in-memory signer and CA for endorsement using generated or provided
// keys.
//
// This package is testonly and non-production since key material should not be loaded into memory
// on the endorsing machine, likely a compilation node. Instead, signing should be offloaded to a
// trusted device whose sole purpose is key management and signing.
package nonprod

import (
	"context"
	"crypto"
	"crypto/rsa" // only used for testing and illustration.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"

	styp "github.com/google/gce-tcb-verifier/sign/types"
)

const (
	// Small sizes are used for faster tests.
	rootBitSize    = 2048
	signingBitSize = 2048
)

// Signer is an in-memory implementation of the Signer interface for endorsing golden measurements.
type Signer struct {
	Now time.Time
	// Keys require randomness to create.
	Rand io.Reader
	Keys map[string]*rsa.PrivateKey
}

func (s *Signer) keyTemplate(issuer, subject KeyInfo, validDays int, publicKey *rsa.PublicKey) *x509.Certificate {
	sn := new(big.Int)
	sn.SetString(subject.PkixName.SerialNumber, 10)
	return &x509.Certificate{
		Subject:            *subject.PkixName,
		Issuer:             *issuer.PkixName,
		SerialNumber:       sn,
		PublicKey:          publicKey,
		NotAfter:           s.Now.Add(time.Duration(validDays) * 24 * time.Hour),
		NotBefore:          s.Now,
		Version:            3,
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
	}
}

// LoadKey stores a given key only if it's the correct type. Otherwise it returns an error.
func (s *Signer) LoadKey(name string, key any) error {
	rkey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("got %T, want *rsa.PrivateKey", key)
	}
	s.setKey(name, rkey)
	return nil
}

func (s *Signer) getKey(name string) (*rsa.PrivateKey, bool) {
	if s.Keys == nil {
		return nil, false
	}
	key, ok := s.Keys[name]
	return key, ok
}

func (s *Signer) setKey(name string, key *rsa.PrivateKey) {
	if s.Keys == nil {
		s.Keys = make(map[string]*rsa.PrivateKey)
	}
	s.Keys[name] = key
}

func (s *Signer) generateKey(keyVersionName string, bitSize int) (*rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(s.Rand, bitSize)
	if err != nil {
		return nil, err
	}
	s.setKey(keyVersionName, priv)
	return priv, nil
}

// GenerateRootKey registers and returns a new key with root key settings.
func (s *Signer) GenerateRootKey(keyVersionName string) (*rsa.PrivateKey, error) {
	return s.generateKey(keyVersionName, rootBitSize)
}

// GenerateSigningKey registers and returns a new key with signing key settings.
func (s *Signer) GenerateSigningKey(keyVersionName string) (*rsa.PrivateKey, error) {
	return s.generateKey(keyVersionName, signingBitSize)
}

func (s *Signer) certifyRootKey(mut styp.CertificateAuthorityMutation, key *Key) error {
	if key.Private == nil {
		priv, err := s.GenerateRootKey(key.Info.KeyVersionName)
		if err != nil {
			return err
		}
		key.Private = priv
	}
	info := key.Info
	s.setKey(info.KeyVersionName, key.Private)
	root := key.Private
	rootCert := key.Cert
	if key.Cert == nil {
		rootCertTpl := s.keyTemplate(info, info, styp.RootValidDays, &root.PublicKey)
		rootCertTpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		rootCertTpl.IsCA = true
		rootCertTpl.BasicConstraintsValid = true
		rootCertBytes, err := x509.CreateCertificate(s.Rand, rootCertTpl, rootCertTpl, root.Public(), root)
		if err != nil {
			return err
		}
		rootCert, err = x509.ParseCertificate(rootCertBytes)
		if err != nil {
			return err
		}
	}
	key.Cert = rootCert
	mut.SetPrimaryRootKeyVersion(info.KeyVersionName)
	mut.SetRootKeyCert(rootCert)
	return nil
}

func (s *Signer) certifySigningKey(root *Key, mut styp.CertificateAuthorityMutation, key Key) error {
	if key.Private == nil {
		priv, err := rsa.GenerateKey(s.Rand, signingBitSize)
		if err != nil {
			return err
		}
		key.Private = priv
	}
	info := key.Info
	signingKey := key.Private
	s.setKey(info.KeyVersionName, signingKey)
	signingCert := key.Cert
	rootInfo := KeyInfo{PkixName: &root.Cert.Subject}
	if key.Cert == nil {
		signingCertTpl := s.keyTemplate(rootInfo, info, styp.SignValidDays, &signingKey.PublicKey)
		signingCertTpl.KeyUsage = x509.KeyUsageDigitalSignature
		signingCertBytes, err := x509.CreateCertificate(s.Rand, signingCertTpl, root.Cert, signingKey.Public(), root.Private)
		if err != nil {
			return err
		}
		signingCert, err = x509.ParseCertificate(signingCertBytes)
		if err != nil {
			return err
		}
	}
	mut.AddSigningKeyCert(info.KeyVersionName, signingCert)
	return nil
}

// KeyInfo represents configurable parts of a fake signer's representation of a key.
type KeyInfo struct {
	// KeyVersionName is the key's unique name (path) for use in signing requests.
	KeyVersionName string
	// PkixName is the whole subject description of the key. If set, overrides CommonName.
	PkixName *pkix.Name
}

// Key represents a precreated private key that will get certificates for a nonprod signer.
type Key struct {
	// Private is optional for creating a fake Signer. If nil, will be generated.
	Private *rsa.PrivateKey
	Cert    *x509.Certificate
	Info    KeyInfo
}

// Options carries all the configurable components for a non-production in-memory signer.
type Options struct {
	Now               time.Time
	Random            io.Reader
	CA                styp.CertificateAuthority
	Root              Key
	PrimarySigningKey Key
	SigningKeys       []Key
}

// DefaultOpts returns the only crypto signing options setting that is supported.
func DefaultOpts() crypto.SignerOpts {
	return &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
} // DELETEME?

// MakeCustomSigner creates a new nonprod Signer with keys of the given names and private keys.
func MakeCustomSigner(ctx context.Context, opts *Options) (*Signer, error) {
	s := &Signer{
		Now:  opts.Now,
		Rand: opts.Random,
		Keys: make(map[string]*rsa.PrivateKey),
	}
	ca := opts.CA
	if ca == nil {
		return nil, fmt.Errorf("signer option CA may not be nil")
	}
	mut := ca.NewMutation()

	if err := s.certifyRootKey(mut, &opts.Root); err != nil {
		return nil, err
	}
	for _, signingKey := range append([]Key{opts.PrimarySigningKey}, opts.SigningKeys...) {
		if err := s.certifySigningKey(&opts.Root, mut, signingKey); err != nil {
			return nil, err
		}
	}
	mut.SetPrimarySigningKeyVersion(opts.PrimarySigningKey.Info.KeyVersionName)
	if err := ca.Finalize(ctx, mut); err != nil {
		return nil, err
	}
	return s, nil
}

// Sign uses the given key to sign the given digest. toSign must be the result of hashing the input
// message with SHA384.
func (s *Signer) Sign(_ context.Context, keyVersionName string, digest styp.Digest, opts crypto.SignerOpts) ([]byte, error) {
	var key *rsa.PrivateKey
	var ok bool
	key, ok = s.getKey(keyVersionName)
	if !ok {
		return nil, fmt.Errorf("invalid key: %q", keyVersionName)
	}
	wantOpts := rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	got, ok := opts.(*rsa.PSSOptions)
	if !ok || *got != wantOpts {
		return nil, fmt.Errorf("got SignerOpts %v, want %v", opts, wantOpts)
	}
	return key.Sign(s.Rand, digest.SHA256, opts)
}

// RsaPublicKeyToPEM returns an RSA public key in its PEM encoding.
func RsaPublicKeyToPEM(pub *rsa.PublicKey) []byte {
	der, _ := asn1.Marshal(struct {
		N []byte
		E int
	}{pub.N.Bytes(), pub.E})
	return pem.EncodeToMemory(&pem.Block{Bytes: der, Type: "RSA PUBLIC KEY"})
}

// PublicKey returns the PEM-encoded public key of the given keyVersionName.
func (s *Signer) PublicKey(_ context.Context, keyVersionName string) ([]byte, error) {
	key, ok := s.getKey(keyVersionName)
	if !ok {
		return nil, fmt.Errorf("invalid key: %s", keyVersionName)
	}
	return RsaPublicKeyToPEM(&key.PublicKey), nil
}

// ClearKeys clears the keys in the signer as part of a wipeout operation.
func (s *Signer) ClearKeys() {
	s.Keys = make(map[string]*rsa.PrivateKey)
}

// DestroyKeyVersion destroys the private key for keyVersionName if it exists.
func (s *Signer) DestroyKeyVersion(keyVersionName string) {
	delete(s.Keys, keyVersionName)
}
