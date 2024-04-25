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
	"strings"
	"time"

	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/google/gce-tcb-verifier/cmd"
	"github.com/google/gce-tcb-verifier/cmd/output"
	"github.com/spf13/cobra"
	"go.uber.org/multierr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	fmpb "google.golang.org/protobuf/types/known/fieldmaskpb"
)

// How many keys to request per iteration of listing them.
const keyPageSize = 100

var (
	// When an old CryptoKeyVersion is destroyed, it will be able to be restored for 2 weeks.
	destroyScheduledDuration = durationpb.New(14 * 24 * time.Hour)
	// ErrNoKeyVersions is returned when bootstrapping fails to find a key version under a created
	// key.
	ErrNoKeyVersions = errors.New("no enabled or pending_generation key versions post key-creation")
	// ErrNoBootstrapContext is returned when gcpkms.FromBootstrapContext can't find the requisite
	// context.
	ErrNoBootstrapContext = errors.New("no gcpkms.BootstrapContext in context")
)

// BootstrapContext encapsulates the KMS-specific options for key bootstrapping.
type BootstrapContext struct {
	// KeyRingID is the base name for the root ring within the given project, location, and key ring.
	RootKeyID string
	// SigningKeyID is the base name for the signing key within the given project, location, and key ring.
	SigningKeyID string
	// SigningKeyOperators are IAM member strings to assign the given accounts as a signing key operator.
	SigningKeyOperators []string
}
type kmsBootstrapKeyType struct{}

var kmsBootstrapKey kmsBootstrapKeyType

// NewBootstrapContext returns ctx extended with the given KmsBootstrapContext.
func NewBootstrapContext(ctx context.Context, f *BootstrapContext) context.Context {
	return context.WithValue(ctx, kmsBootstrapKey, f)
}

// FromBootstrapContext returns the KmsBootstrapContext in the context if it exists.
func FromBootstrapContext(ctx context.Context) (*BootstrapContext, error) {
	f, ok := ctx.Value(kmsBootstrapKey).(*BootstrapContext)
	if !ok {
		return nil, ErrNoBootstrapContext
	}
	return f, nil
}

// Returns true if enabled, false if pending for the returned CryptoKeyVersion.
func (m *Manager) getEnabledOrPendingKeyVersion(ctx context.Context, parent string) (*kmspb.CryptoKeyVersion, error) {
	// Go through all the key versions for the key to find an enabled (done) or pending_generation
	// version. There might be multiple disabled, destroyed, or scheduled for destruction due to
	// rotations and wipeouts.
	var pageToken string
	var version *kmspb.CryptoKeyVersion
	for {
		vers, err := m.KeyClient.ListCryptoKeyVersions(ctx,
			&kmspb.ListCryptoKeyVersionsRequest{
				Parent:    parent,
				PageSize:  keyPageSize,
				PageToken: pageToken,
			})
		if err != nil {
			return nil, err
		}
		if vers.GetTotalSize() == 0 {
			return nil, fmt.Errorf("new CryptoKey has missing initial version")
		}
		for _, v := range vers.GetCryptoKeyVersions() {
			if v.GetState() == kmspb.CryptoKeyVersion_ENABLED {
				return v, nil
			}
			// Set the version in case there's a different version that's enabled that's later in the
			// list.
			if v.GetState() == kmspb.CryptoKeyVersion_PENDING_GENERATION {
				version = v
			}
		}
		if len(vers.GetCryptoKeyVersions()) < keyPageSize {
			break
		}
		pageToken = vers.GetNextPageToken()
	}
	if version == nil {
		return nil, ErrNoKeyVersions
	}
	return version, nil
}

// Returns a cryptoKeyVersion name under keyName that is in state ENABLED or an error.
func (m *Manager) waitForKeyGen(ctx context.Context, keyName string) (string, error) {
	version, err := m.getEnabledOrPendingKeyVersion(ctx, keyName)
	if errors.Is(err, ErrNoKeyVersions) {
		version, err = m.KeyClient.CreateCryptoKeyVersion(ctx,
			&kmspb.CreateCryptoKeyVersionRequest{Parent: keyName})
	}
	if err != nil {
		return "", fmt.Errorf("could not get crypto key version of %q: %w", keyName, err)
	}
	if version.GetState() == kmspb.CryptoKeyVersion_ENABLED {
		return version.GetName(), nil
	}

	return m.waitForKeyVersionGen(ctx, version.GetName())
}

func (m *Manager) waitForKeyVersionGen(ctx context.Context, keyVersionName string) (string, error) {
	// The asymmetric key generation can take time after receiving a response, so poll for when the
	// key is enabled before returning.
	getReq := &kmspb.GetCryptoKeyVersionRequest{Name: keyVersionName}
	for {
		updated, err := m.KeyClient.GetCryptoKeyVersion(ctx, getReq)
		if err != nil {
			return "", fmt.Errorf("could not poll crypto key version %q: %w", keyVersionName, err)
		}

		switch updated.GetState() {
		case kmspb.CryptoKeyVersion_ENABLED:
			return updated.GetName(), nil
		case kmspb.CryptoKeyVersion_PENDING_GENERATION:
			output.Infof(ctx, "waiting for key version generation...")
		default:
			return "", fmt.Errorf("crypto key version in unexpected state %v, want %s",
				updated.GetState(), "ENABLED or PENDING_GENERATION")
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("timeout waiting for key generation of %q", keyVersionName)
		case <-time.After(5 * time.Second):
		}
	}
}

// createNewHSMKey creates an HSM key in m's keyring with the algorithm expected for the root
// signing key, or returns an error.
func (m *Manager) createNewHSMKey(ctx context.Context, keyID string) error {
	_, err := m.KeyClient.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      m.FullKeyRingName(),
		CryptoKeyId: keyID,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm:       kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
			},
		},
	})
	return err
}

func (m *Manager) createNewSigningKey(ctx context.Context, keyID string) error {
	_, err := m.KeyClient.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      m.FullKeyRingName(),
		CryptoKeyId: keyID,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
				Algorithm:       kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
			},
			DestroyScheduledDuration: destroyScheduledDuration,
		},
	})
	return err
}

func (m *Manager) grantSigningPermissions(ctx context.Context) error {
	kbc, err := FromBootstrapContext(ctx)
	if err != nil {
		return err
	}
	keyName := m.FullKeyName(kbc.SigningKeyID)
	// The signing key should be accessible by the signer account. The signer account is not bound
	// at the project layer to restrict the signer's privileges to only what is necessary.
	if _, err := m.IAMClient.SetIamPolicy(ctx, &iampb.SetIamPolicyRequest{
		Policy: &iampb.Policy{
			Bindings: []*iampb.Binding{
				{
					Role:    "roles/cloudkms.cryptoOperator",
					Members: kbc.SigningKeyOperators,
				},
			},
		},
		UpdateMask: &fmpb.FieldMask{Paths: []string{"bindings"}},
		Resource:   keyName,
	}); err != nil {
		return fmt.Errorf("could not set IAM policy for signing key %q: %w", keyName, err)
	}
	return nil
}

func (m *Manager) recreateKeyRing(ctx context.Context) error {
	_, err := m.KeyClient.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    m.FullLocationName(),
		KeyRing:   &kmspb.KeyRing{},
		KeyRingId: m.KeyRingID,
	})
	if status.Code(err) == codes.AlreadyExists && !output.AllowRecoverableError(ctx) {
		return err
	}
	return nil
}

type keyCreatorFn func(ctx context.Context, keyID string) error

// Calls f() to get a CryptoKey name, then it gets an enabled key version under the key. Returns
// the cryptoKeyVersion name or an error.
func (m *Manager) recreateCryptoKey(ctx context.Context, f keyCreatorFn, keyID string) (string, error) {
	err := f(ctx, keyID)
	created := status.Code(err) == codes.AlreadyExists
	if err != nil && (!created || !output.AllowRecoverableError(ctx)) {
		return "", fmt.Errorf("could not create key %s: %w", keyID, err)
	}
	keyName := m.FullKeyName(keyID)
	if created {
		output.Infof(ctx, "Created key: %s", keyName)
	} else {
		output.Warningf(ctx, "Key already exists: %s", keyName)
	}
	return m.waitForKeyGen(ctx, keyName)
}

// CreateNewRootKey establishes a new key for use as the root CA key.
func (m *Manager) CreateNewRootKey(ctx context.Context) (string, error) {
	kbc, err := FromBootstrapContext(ctx)
	if err != nil {
		return "", err
	}
	if err := m.recreateKeyRing(ctx); err != nil {
		return "", fmt.Errorf("could not create key ring: %w", err)
	}

	return m.recreateCryptoKey(ctx, m.createNewHSMKey, kbc.RootKeyID)
}

// CreateFirstSigningKey is called during CA bootstrapping to create the first signing key that
// can be used for endorse.
func (m *Manager) CreateFirstSigningKey(ctx context.Context) (string, error) {
	kbc, err := FromBootstrapContext(ctx)
	if err != nil {
		return "", err
	}
	name, err := m.recreateCryptoKey(ctx, m.createNewSigningKey, kbc.SigningKeyID)
	if err != nil {
		return "", fmt.Errorf("could not create signing key: %w", err)
	}
	if err := m.grantSigningPermissions(ctx); err != nil {
		return "", err
	}
	output.Infof(ctx, "Created first signing key %s with signing permissions for %s", name,
		strings.Join(kbc.SigningKeyOperators, "|"))
	return name, nil
}

// BootstrapContext is also a command component to register its flags and context value.

func addSigningKeyIDFlag(cmd *cobra.Command, signingKeyID *string) {
	cmd.PersistentFlags().StringVar(signingKeyID, "signing_key", "gce-uefi-signing-key",
		"The name of the signing key.")
}

// AddFlags adds GCP KMS cryptoKey name flags for the root and signing keys to create.
func (kbc *BootstrapContext) AddFlags(cmd *cobra.Command) {
	cmd.SetContext(NewBootstrapContext(cmd.Context(), kbc))
	cmd.PersistentFlags().StringVar(&kbc.RootKeyID, "root_key", "gce-cc-tcb-root",
		"The name of the root key.")
	addSigningKeyIDFlag(cmd, &kbc.SigningKeyID)
	cmd.PersistentFlags().StringSliceVar(&kbc.SigningKeyOperators, "signing_key_operators",
		nil,
		"The service accounts given subordinate access to only the signing key.")
}

// PersistentPreRunE returns an error if either root_key or signing_key are unset.
func (kbc *BootstrapContext) PersistentPreRunE(*cobra.Command, []string) (err error) {
	if len(kbc.SigningKeyOperators) == 0 {
		err = fmt.Errorf("--signing_key_operators must be set to at least one role")
	}
	return multierr.Combine(err, cmd.MustBeNonempty("root_key", &kbc.RootKeyID),
		cmd.MustBeNonempty("signing_key", &kbc.SigningKeyID))
}

// InitContext returns the given context without changes.
func (kbc *BootstrapContext) InitContext(ctx context.Context) (context.Context, error) {
	return ctx, nil
}
