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
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/net/context"

	"github.com/google/gce-tcb-verifier/cmd/output"
	"github.com/google/gce-tcb-verifier/keys"
)

var (
	// ErrNoBootstrapContext is returned when FromBootstrapContext can't find the requisite
	// context.
	ErrNoBootstrapContext = errors.New("no BootstrapContext in context")
)

// BootstrapContext represents configurable names and locations for the key assets to create.
type BootstrapContext struct {
	// RootKeyCommonName is the X.509 certificate common name for the root key subject
	RootKeyCommonName string
	// SigningKeyCommonName is the X.509 certificate common name for the signing key subject
	SigningKeyCommonName string
	// RootKeySerial is the serial number to assign the root key.
	RootKeySerial *big.Int
	// SigningKeySerial is the serial number to assign the first signing key.
	SigningKeySerial *big.Int
	// Now is the timestamp for all certificates created during bootstrapping.
	Now time.Time
}

type bootstrapKeyType struct{}

var bootstrapKey bootstrapKeyType

// NewBootstrapContext returns ctx extended with the given BootstrapContext.
func NewBootstrapContext(ctx context.Context, f *BootstrapContext) context.Context {
	return context.WithValue(ctx, bootstrapKey, f)
}

// FromBootstrapContext returns the BootstrapContext in the context if it exists.
func FromBootstrapContext(ctx context.Context) (*BootstrapContext, error) {
	f, ok := ctx.Value(bootstrapKey).(*BootstrapContext)
	if !ok {
		return nil, ErrNoBootstrapContext
	}
	return f, nil
}

// Bootstrap creates a new chain of trust with its own key ring, root key, signing key, and
// key certificates. Certificates are uploaded to the context's private bucket.
func Bootstrap(ctx context.Context) error {
	c, err := keys.FromContext(ctx)
	if err != nil {
		return err
	}
	if err := c.CA.PrepareResources(ctx); err != nil {
		return fmt.Errorf("could not prepare certificate authority resources: %w", err)
	}

	rootKeyVersion, err := c.Manager.CreateNewRootKey(ctx)
	if err != nil {
		return fmt.Errorf("could not create root key: %w", err)
	}

	signingKeyVersion, err := c.Manager.CreateFirstSigningKey(ctx)
	if err != nil {
		return fmt.Errorf("could not create signing key: %w", err)
	}

	mut := c.CA.NewMutation()
	mut.SetPrimaryRootKeyVersion(rootKeyVersion)
	mut.SetPrimarySigningKeyVersion(signingKeyVersion)

	rootCert, err := InternalSignAndUpload(ctx, &InternalSignAndUploadRequest{
		Mutation:              mut,
		SubjectKeyVersionName: rootKeyVersion,
		IssuerKeyVersionName:  rootKeyVersion,
	})
	if err != nil {
		return fmt.Errorf("could not bootstrap root key: %w", err)
	}
	output.Infof(ctx, "Root key certificate uploaded for %q", rootKeyVersion)

	// The signing key initial version is created. Just sign and upload.
	if _, err := InternalSignAndUpload(ctx, &InternalSignAndUploadRequest{
		Mutation:              mut,
		Issuer:                rootCert,
		SubjectKeyVersionName: signingKeyVersion,
		IssuerKeyVersionName:  rootKeyVersion,
	}); err != nil {
		return err
	}
	output.Infof(ctx, "Initial signing key certificate uploaded.")
	if err := c.CA.Finalize(ctx, mut); err != nil {
		return err
	}
	output.Infof(ctx, "Initial manifest created.")

	return nil
}
