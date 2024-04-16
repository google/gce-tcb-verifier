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

// Package memkm provides an in-memory keys.ManagerInterface implementation. Used for testing.
package memkm

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"golang.org/x/net/context"
	"os"
	"strconv"
	"strings"

	"github.com/google/gce-tcb-verifier/cmd/output"
	"github.com/google/gce-tcb-verifier/keys"
	"github.com/google/gce-tcb-verifier/rotate"
	"github.com/google/gce-tcb-verifier/sign/nonprod"
	sops "github.com/google/gce-tcb-verifier/sign/ops"
	"github.com/google/gce-tcb-verifier/testing/devkeys"
	"github.com/google/gce-tcb-verifier/testing/nonprod/certs"
	"github.com/google/gce-tcb-verifier/testing/testsign"
	"github.com/spf13/cobra"
)

const (
	// defaultRootKeyName is the default name of the root key version name.
	defaultRootKeyName = "root"
	// defaultPrimarySigningKeyName is the default name of the first primary signing key version name.
	defaultPrimarySigningKeyName = "primarySigningKey"
)

// T is the type of the memkm key manager.
type T struct {
	Signer                *nonprod.Signer
	RootKeyName           string
	PrimarySigningKeyName string
}

func (*T) rootTemplateFrom(ctx context.Context, subjectPubKey any) (*x509.Certificate, error) {
	c, err := keys.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if c.CA == nil {
		return nil, keys.ErrNoCertificateAuthority
	}
	rootName, err := c.CA.PrimaryRootKeyVersion(ctx)
	if err != nil {
		return nil, err
	}
	if rootCert, err := sops.IssuerCertFromBundle(ctx, c.CA, rootName); err == nil {
		return certs.TemplateFromCert(ctx, rootCert, subjectPubKey)
	}

	bc, err := rotate.FromBootstrapContext(ctx)
	if err != nil {
		return nil, err
	}
	output.Warningf(ctx, "root %q does not have a certificate. Using Google template", rootName)

	return sops.GoogleCertificateTemplate(&sops.GoogleCertTemplate{
		Serial:            bc.RootKeySerial,
		PublicKey:         subjectPubKey,
		NotBefore:         bc.Now,
		SubjectCommonName: bc.RootKeyCommonName,
	})
}

func (k *T) signingKeyTemplateFrom(ctx context.Context, issuer *x509.Certificate, subjectPubKey any) (*x509.Certificate, error) {
	c, err := keys.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	primarySigningKey, err := c.CA.PrimarySigningKeyVersion(ctx)
	if err != nil {
		return nil, err
	}
	if signCertDER, err := c.CA.Certificate(ctx, primarySigningKey); err == nil {
		signCert, err := x509.ParseCertificate(signCertDER)
		if err != nil {
			return nil, err
		}
		return certs.TemplateFromCert(ctx, signCert, subjectPubKey)
	}

	output.Warningf(ctx, "signer %q does not have a certificate. Using Google template", primarySigningKey)
	skc, err := certs.SigningKeyContextFrom(ctx)
	if err != nil {
		return nil, err
	}
	return sops.GoogleCertificateTemplate(&sops.GoogleCertTemplate{
		Serial:            skc.SigningKeySerial,
		PublicKey:         subjectPubKey,
		Issuer:            issuer,
		NotBefore:         skc.Now,
		SubjectCommonName: skc.SigningKeyCommonName,
	})
}

// CertificateTemplate returns a certificate template that will be used for signing.
func (k *T) CertificateTemplate(ctx context.Context, issuer *x509.Certificate, subjectPubKey any) (*x509.Certificate, error) {
	if issuer == nil {
		return k.rootTemplateFrom(ctx, subjectPubKey)
	}
	return k.signingKeyTemplateFrom(ctx, issuer, subjectPubKey)
}

func (k *T) keyExists(ctx context.Context, keyVersionName string) error {
	c, err := keys.FromContext(ctx)
	if err != nil {
		return err
	}
	if c.CA == nil {
		return keys.ErrNoCertificateAuthority
	}
	if !output.AllowOverwrite(ctx) {
		if _, err := k.Signer.PublicKey(ctx, keyVersionName); err == nil {
			return os.ErrExist
		}
	}
	return nil
}

// CreateFirstSigningKey is called during CA bootstrapping to create the first signing key that
// can be used for endorse.
func (k *T) CreateFirstSigningKey(ctx context.Context) (string, error) {
	primarySigningKeyName := k.getPrimarySigningKeyName()
	if err := k.keyExists(ctx, primarySigningKeyName); err != nil {
		return "", err
	}
	if _, err := k.Signer.GenerateSigningKey(primarySigningKeyName); err != nil {
		return "", err
	}
	return primarySigningKeyName, nil
}

// BumpName returns a given name with a counter suffix added at 1 or increased by 1, following '_'.
func BumpName(name string) string {
	var lastNum uint64
	pieces := strings.Split(name, "_")
	prefix := name
	if len(pieces) > 1 {
		var err error
		lastNum, err = strconv.ParseUint(pieces[len(pieces)-1], 10, 64)
		if err == nil {
			prefix = strings.Join(pieces[:len(pieces)-1], "_")
		}
	}
	return fmt.Sprintf("%s_%d", prefix, lastNum+1)
}

// CreateNewSigningKeyVersion is callable after CreateNewSigningKey, and is meant for key
// rotation. The signing key's name ought to be available from the context.
func (k *T) CreateNewSigningKeyVersion(ctx context.Context) (string, error) {
	c, err := keys.FromContext(ctx)
	if err != nil {
		return "", err
	}
	keyVersionName, err := c.CA.PrimarySigningKeyVersion(ctx)
	if err != nil {
		return "", err
	}
	nextKeyVersionName := BumpName(keyVersionName)
	if _, err := k.Signer.GenerateSigningKey(nextKeyVersionName); err != nil {
		return "", err
	}
	return nextKeyVersionName, nil
}

func (k *T) getRootKeyName() string {
	if k.RootKeyName == "" {
		k.RootKeyName = defaultRootKeyName
	}
	return k.RootKeyName
}

func (k *T) getPrimarySigningKeyName() string {
	if k.PrimarySigningKeyName == "" {
		k.PrimarySigningKeyName = defaultPrimarySigningKeyName
	}
	return k.PrimarySigningKeyName
}

// CreateNewRootKey establishes a new key for use as the root CA key.
func (k *T) CreateNewRootKey(ctx context.Context) (string, error) {
	rootName := k.getRootKeyName()
	if er := k.keyExists(ctx, rootName); er != nil {
		return "", er
	}
	if _, err := k.Signer.GenerateRootKey(rootName); err != nil {
		return "", err
	}
	return rootName, nil
}

// DestroyKeyVersion destroys a single key version.
func (k *T) DestroyKeyVersion(ctx context.Context, keyVersionName string) error {
	k.Signer.DestroyKeyVersion(keyVersionName)
	return nil
}

// Wipeout destroys all keys managed by this manager.
func (k *T) Wipeout(ctx context.Context) error {
	k.Signer.ClearKeys()
	return nil
}

// memkm implements CommandComponent to compose well in the CLI construction.

// InitContext extends the given context with whatever else the component needs before execution.
func (k *T) InitContext(ctx context.Context) (context.Context, error) {
	c, err := keys.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	// These are set in InitContext rather than AddFlags to avoid them getting used outside of Run.
	c.Signer = k.Signer
	c.Manager = k
	return ctx, nil
}

// AddFlags adds any implementation-specific flags for this command component.
func (k *T) AddFlags(cmd *cobra.Command) {}

// PersistentPreRunE returns an error if the results of the parsed flags constitute an error.
func (k *T) PersistentPreRunE(cmd *cobra.Command, args []string) error { return nil }

// TestOnlyT returns a T instance populated with pre-generated keys for development.
func TestOnlyT() *T {
	s := &nonprod.Signer{Rand: testsign.RootRand()}
	rb, _ := pem.Decode(devkeys.RootPEM)
	root, _ := x509.ParsePKCS8PrivateKey(rb.Bytes)
	pb, _ := pem.Decode(devkeys.PrimarySigningKeyPEM)
	primary, _ := x509.ParsePKCS8PrivateKey(pb.Bytes)
	s.LoadKey("root", root)
	s.LoadKey("primarySigningKey", primary)
	return &T{Signer: s}
}
