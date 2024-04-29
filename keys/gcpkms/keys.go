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
	"crypto/x509"
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/multierr"

	"cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/kms/apiv1/kmspb"

	"github.com/google/gce-tcb-verifier/cmd"
	"github.com/google/gce-tcb-verifier/keys"
	"github.com/google/gce-tcb-verifier/rotate"
)

// Manager defines KMS-specific input parameters for key operations.
type Manager struct {
	// Project is the GCP project name that will own the assets.
	Project string
	// Location is the GCP location name that will host the key ring.
	Location string
	// KeyRingID is the base name for the key ring within the given project and location.
	KeyRingID string
	// KeyClient is a connected CloudKMS client.
	KeyClient kmspb.KeyManagementServiceClient
	// IAMClient is a connected IAM client.
	IAMClient iampb.IAMPolicyClient
}

// FullLocationName returns the location-based parent resource name as CloudKMS understands names
// given the project and location names.
func (m *Manager) FullLocationName() string {
	return fmt.Sprintf("projects/%s/locations/%s", m.Project, m.Location)
}

// FullKeyRingName returns the keyRing name as CloudKMS understands names given the project,
// location, and the keyRing name.
func (m *Manager) FullKeyRingName() string {
	return fmt.Sprintf("%s/keyRings/%s", m.FullLocationName(), m.KeyRingID)
}

// FullKeyName returns the key name as CloudKMS understands names given the project, location, key
// ring name, and key name.
func (m *Manager) FullKeyName(keyName string) string {
	return fmt.Sprintf("%s/cryptoKeys/%s", m.FullKeyRingName(), keyName)
}

func destroyableState(state kmspb.CryptoKeyVersion_CryptoKeyVersionState) (bool, error) {
	switch state {
	case kmspb.CryptoKeyVersion_ENABLED:
		return true, nil
	case kmspb.CryptoKeyVersion_DISABLED:
		return true, nil
	case kmspb.CryptoKeyVersion_DESTROYED:
		return false, nil
	case kmspb.CryptoKeyVersion_DESTROY_SCHEDULED:
		return false, nil
	case kmspb.CryptoKeyVersion_PENDING_IMPORT:
		return false, nil
	case kmspb.CryptoKeyVersion_PENDING_GENERATION:
		return false, nil
	case kmspb.CryptoKeyVersion_IMPORT_FAILED:
		return false, nil
	case kmspb.CryptoKeyVersion_GENERATION_FAILED:
		return false, nil
	case kmspb.CryptoKeyVersion_PENDING_EXTERNAL_DESTRUCTION:
		return false, nil
	case kmspb.CryptoKeyVersion_EXTERNAL_DESTRUCTION_FAILED:
		return false, nil
	}
	return false, fmt.Errorf("unknown key state %d", state)
}

func (m *Manager) wipeoutKey(ctx context.Context, keyName string) error {
	var pageToken string
	var result error
	for {
		resp, err := m.KeyClient.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{
			Parent:    keyName,
			PageSize:  keyPageSize,
			PageToken: pageToken,
		})
		if err != nil {
			return fmt.Errorf("could not list cryptoKeyVersions in %q: %w", keyName, err)
		}
		for _, kver := range resp.GetCryptoKeyVersions() {
			destroyable, err := destroyableState(kver.GetState())
			result = multierr.Append(result, err)
			if !destroyable {
				continue
			}
			_, err = m.KeyClient.DestroyCryptoKeyVersion(ctx,
				&kmspb.DestroyCryptoKeyVersionRequest{Name: kver.GetName()})
			result = multierr.Append(result, err)
		}
		if len(resp.GetCryptoKeyVersions()) < keyPageSize {
			break
		}
		pageToken = resp.GetNextPageToken()
	}
	return result
}

// Wipeout destroys all keys created and persisted by this interface.
func (m *Manager) Wipeout(ctx context.Context) error {
	var pageToken string
	var result error
	keyRing := m.FullKeyRingName()
	for {
		resp, err := m.KeyClient.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{
			Parent: keyRing, PageSize: keyPageSize, PageToken: pageToken})
		if err != nil {
			return fmt.Errorf("could not list cryptoKeys in %q: %w", keyRing, err)
		}
		for _, key := range resp.GetCryptoKeys() {
			result = multierr.Append(result, m.wipeoutKey(ctx, key.GetName()))
		}
		if len(resp.GetCryptoKeys()) < keyPageSize {
			break
		}
		pageToken = resp.GetNextPageToken()
	}
	return result
}

// CertificateTemplate returns a certificate template that will be used for signing.
func (m *Manager) CertificateTemplate(ctx context.Context, issuer *x509.Certificate, subjectPubKey any) (*x509.Certificate, error) {
	return rotate.GoogleCertificateTemplate(ctx, issuer, subjectPubKey)
}

// AddFlags defines GCP KMS-specific key management flags for all key subcommands.
func (m *Manager) AddFlags(cmd *cobra.Command) {
	flags := cmd.PersistentFlags()
	flags.StringVar(&m.Project, "project", "cvm-fw-signer-dev",
		"The project name that owns the assets.")
	flags.StringVar(&m.Location, "location", "us-west1", "The location of the key ring.")
	flags.StringVar(&m.KeyRingID, "key_ring", "gce-cc-keys",
		"The name of the key ring in the location.")
}

// InitContext initializes keys.Context's Manager to the gcskms.Manager and the signer to a gcpkms
// Signer.
func (m *Manager) InitContext(ctx context.Context) (context.Context, error) {
	c, err := keys.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	c.Manager = m
	c.Signer = &Signer{Manager: m}

	return ctx, nil
}

// PersistentPreRunE returns an error if any flag values are invalid.
func (m *Manager) PersistentPreRunE(*cobra.Command, []string) error {
	return multierr.Combine(cmd.MustBeNonempty("project", &m.Project),
		cmd.MustBeNonempty("location", &m.Location),
		cmd.MustBeNonempty("key_ring", &m.KeyRingID),
	)
}
