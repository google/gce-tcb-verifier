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

package gcpkms

import (
	"context"
	"errors"
	"fmt"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/google/gce-tcb-verifier/cmd"
	"github.com/spf13/cobra"
)

var (
	// ErrNoSigningKeyContext is returned when gcpkms.FromSigningKeyContext can't find the requisite
	// context.
	ErrNoSigningKeyContext = errors.New("no gcpkms.SigningKeyContext in context")
)

// SigningKeyContext holds the KMS-specific arguments needed for specifying a key rotation.
type SigningKeyContext struct {
	// SigningKeyID is the base name for the signing key within the given project, location, and key
	// ring.
	SigningKeyID string
}

type kmsSigningKeyKeyType struct{}

var kmsSigningKeyKey kmsSigningKeyKeyType

// NewSigningKeyContext returns ctx extended with the given gcpkms.SigningKeyContext.
func NewSigningKeyContext(ctx context.Context, f *SigningKeyContext) context.Context {
	return context.WithValue(ctx, kmsSigningKeyKey, f)
}

// FromSigningKeyContext returns the gcpkms.SigningKeyContext in the context if it exists.
func FromSigningKeyContext(ctx context.Context) (*SigningKeyContext, error) {
	f, ok := ctx.Value(kmsSigningKeyKey).(*SigningKeyContext)
	if !ok {
		return nil, ErrNoSigningKeyContext
	}
	return f, nil
}

// CreateNewSigningKeyVersion is callable after CreateNewSigningKey, and is meant for key
// rotation. The signing key's name ought to be available from the context.
func (m *Manager) CreateNewSigningKeyVersion(ctx context.Context) (string, error) {
	skc, err := FromSigningKeyContext(ctx)
	if err != nil {
		return "", err
	}
	keyName := m.FullKeyName(skc.SigningKeyID)
	key, err := m.KeyClient.CreateCryptoKeyVersion(ctx,
		&kmspb.CreateCryptoKeyVersionRequest{Parent: keyName})
	if err != nil {
		return "", fmt.Errorf("error creating new key version for %q: %v", keyName, err)
	}
	return m.waitForKeyVersionGen(ctx, key.GetName())
}

// DestroyKeyVersion destroys a single key version.
func (m *Manager) DestroyKeyVersion(ctx context.Context, keyVersionName string) error {
	if _, err := m.KeyClient.DestroyCryptoKeyVersion(ctx,
		&kmspb.DestroyCryptoKeyVersionRequest{Name: keyVersionName}); err != nil {
		return fmt.Errorf("error destroying previous signing key %q: %w", keyVersionName, err)
	}
	return nil
}

// SigningKeyContext is a CommandComponent.

// AddFlags adds a GCP KMS cryptoKey name flag for the signing key to rotate.
func (skc *SigningKeyContext) AddFlags(cmd *cobra.Command) {
	cmd.SetContext(NewSigningKeyContext(cmd.Context(), skc))
	addSigningKeyIDFlag(cmd, &skc.SigningKeyID)
}

// PersistentPreRunE returns an error if signing_key is unset.
func (skc *SigningKeyContext) PersistentPreRunE(*cobra.Command, []string) error {
	return cmd.MustBeNonempty("signing_key", &skc.SigningKeyID)
}

// InitContext returns the given context without changes.
func (*SigningKeyContext) InitContext(ctx context.Context) (context.Context, error) {
	return ctx, nil
}
