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

// Package rotate ensures rotated signing keys for CC TCB endorsement have certificates in GCS.
package rotate

import (
	"crypto/x509"
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"math/big"
	"time"

	"github.com/google/gce-tcb-verifier/cmd/output"
	"github.com/google/gce-tcb-verifier/keys"
	sops "github.com/google/gce-tcb-verifier/sign/ops"
	styp "github.com/google/gce-tcb-verifier/sign/types"
	"go.uber.org/multierr"
)

var (
	// ErrKeyIsUsed is the error that UploadKeyCert returns if the keyName already had a certificate
	// uploaded.
	ErrKeyIsUsed = errors.New("key already exists")
	// ErrNoSigningKeyContext is returned when key rotation is called without a SigningKeyContext in
	// the context.
	ErrNoSigningKeyContext = errors.New("no rotate.SigningKeyContext provided")
)

// SigningKeyContext represents configurable certificate information for rotating the signing key.
type SigningKeyContext struct {
	// SigningKeyCommonName is the X.509 certificate common name for the signing key subject
	SigningKeyCommonName string
	// SigningKeySerial is the serial number to give to the signing key certificate's subject.
	SigningKeySerial *big.Int

	// Now is the time to use for certification.
	Now time.Time
}

type signingKeyContextKeyType struct{}

var signingKeyContextKey signingKeyContextKeyType

// NewSigningKeyContext returns ctx extended with the given rotate context.
func NewSigningKeyContext(ctx context.Context, r *SigningKeyContext) context.Context {
	return context.WithValue(ctx, signingKeyContextKey, r)
}

// FromSigningKeyContext returns the rotate context within ctx if it exists.
func FromSigningKeyContext(ctx context.Context) (*SigningKeyContext, error) {
	r, ok := ctx.Value(signingKeyContextKey).(*SigningKeyContext)
	if !ok {
		return nil, ErrNoSigningKeyContext
	}
	return r, nil
}

// keyRequest specifies which key to rotate with a new root-signed certificate, given the
// certificate's creation time and subject key's common name.
type keyRequest struct {
	// keys.Context info needed for the key request.
	ca      styp.CertificateAuthority
	manager keys.ManagerInterface
	// Intermediate results during rotation
	kver           string
	currentVersion string
	currentRoot    string
	issuer         *x509.Certificate
	mut            styp.CertificateAuthorityMutation
}

// Key creates a new CryptoKeyVersion for the given keyName, signs it, uploads the cert,
// sets the primary key version to the new version, and then destroys the old key.
func Key(ctx context.Context) (string, error) {
	c, err := keys.FromContext(ctx)
	if err != nil {
		return "", err
	}
	if c.CA == nil {
		return "", keys.ErrNoCertificateAuthority
	}
	if c.Manager == nil {
		return "", keys.ErrNoManager
	}
	req := &keyRequest{ca: c.CA, manager: c.Manager}

	// The steps of rotation store intermediate results in the request
	// for the error handling to sequence cleanly.
	if err := multierr.Combine(
		req.createNewSigningKeyVersion(ctx),
		req.getCurrentInfo(ctx),
		req.signAndAdd(ctx),
		req.updatePrimaryAndDestroy(ctx),
		req.finalize(ctx),
	); err != nil {
		return "", err
	}

	return req.kver, nil
}

func (r *keyRequest) createNewSigningKeyVersion(ctx context.Context) error {
	key, err := r.manager.CreateNewSigningKeyVersion(ctx)
	if err != nil {
		return err
	}
	r.kver = key
	return nil
}

func (r *keyRequest) getCurrentInfo(ctx context.Context) error {
	// If we ever change the root, we want to be able to use the root we've stored for certifying the
	// current signing key.
	currentVersion, err := r.ca.PrimarySigningKeyVersion(ctx)
	if err != nil {
		return fmt.Errorf("rotation cannot determine current primary key version: %v", err)
	}
	primaryRoot, err := r.ca.PrimaryRootKeyVersion(ctx)
	if err != nil {
		return fmt.Errorf("rotation cannot determine current root key version: %v", err)
	}
	issuer, err := sops.IssuerCertFromBundle(ctx, r.ca, currentVersion)
	if err != nil {
		return fmt.Errorf("could not get issuer certificate for key %q: %v", currentVersion, err)
	}
	r.currentRoot = primaryRoot
	r.issuer = issuer
	r.currentVersion = currentVersion
	return nil
}

func (r *keyRequest) signAndAdd(ctx context.Context) error {
	if r.currentRoot == "" || r.kver == "" || r.issuer == nil {
		return fmt.Errorf("cannot sign signing key cert, current root: %q, kver %q, issuer %v",
			r.currentRoot, r.kver, r.issuer)
	}
	if r.currentVersion == "" {
		output.Infof(ctx, "Certifying first signing key")
	}
	r.mut = r.ca.NewMutation()
	_, err := InternalSignAndUpload(ctx, &InternalSignAndUploadRequest{
		Mutation:              r.mut,
		Issuer:                r.issuer,
		SubjectKeyVersionName: r.kver,
		IssuerKeyVersionName:  r.currentRoot,
	})
	return err
}

func (r *keyRequest) updatePrimaryAndDestroy(ctx context.Context) error {
	if r.kver == "" || r.mut == nil {
		return fmt.Errorf("cannot update primary with signing key %q, mutation %v", r.kver, r.mut)
	}
	r.mut.SetPrimarySigningKeyVersion(r.kver)

	// Destroy the old version if it existed.
	if r.currentVersion != "" {
		output.Infof(ctx, "Destroying previous signing key %q", r.currentVersion)
		if err := r.manager.DestroyKeyVersion(ctx, r.currentVersion); err != nil {
			return err
		}
	}
	return nil
}

func (r *keyRequest) finalize(ctx context.Context) error {
	return r.ca.Finalize(ctx, r.mut)
}
