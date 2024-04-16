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

// Package gcsca implements the sign.CertificateAuthority interface with GCS backing.
package gcsca

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"io"
	"strings"

	"github.com/google/gce-tcb-verifier/cmd"
	"github.com/google/gce-tcb-verifier/cmd/output"
	"github.com/google/gce-tcb-verifier/keys"
	cpb "github.com/google/gce-tcb-verifier/proto/certificates"
	"github.com/google/gce-tcb-verifier/rotate"
	styp "github.com/google/gce-tcb-verifier/sign/types"
	stops "github.com/google/gce-tcb-verifier/storage/ops"
	"github.com/google/gce-tcb-verifier/storage/storagei"
	"github.com/spf13/cobra"
	"go.uber.org/multierr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"
)

// ManifestObjectName is the objectName for the CA's key manifest file.
const ManifestObjectName = "keyManifest.textproto"

var (
	// ErrKeyExists is the error that Finalize returns if a mutation attempts to add an existing key and
	// Overwrite is not true.
	ErrKeyExists = errors.New("key exists in certificate authority")
)

// CertificateAuthority implements both the sign.CertificateAuthority interface with GCS backing,
// and cmd.CommandComponent
type CertificateAuthority struct {
	// RootPath is the object name for the root key certificate in the context's private bucket.
	RootPath string
	// PrivateBucket is the GCS bucket the CA certs reside in.
	PrivateBucket string
	// SigningCertDirInGCS is the path to the directory that stores signing key certificates in the
	// GCS bucket.
	SigningCertDirInGCS string
	// Storage is a storage client the CA uses to read and write files.
	Storage storagei.Client
	// SigningKeyPrefix is the expected keyVersionName prefix for certificate bundles.
	SigningKeyPrefix string

	// A cache of the current key manifest. Changes are flushed to GCS by writing the whole file.
	manifest *cpb.GCECertificateManifest
}

// AddFlags adds any implementation-specific flags for the command component.
func (ca *CertificateAuthority) AddFlags(cmd *cobra.Command) {
	flag := cmd.PersistentFlags()
	flag.StringVar(&ca.PrivateBucket, "bucket", "certs-dev",
		"The name of the private GCS bucket that stores certificates.")
	flag.StringVar(&ca.SigningCertDirInGCS, "cert_dir", "signer_certs",
		"Path to the signer certificate directory in the bucket.")
	flag.StringVar(&ca.RootPath, "root_path", "", "Path to root key certificate in --bucket")
}

// PersistentPreRunE returns an error if the results of the parsed flags constitute an error.
func (ca *CertificateAuthority) PersistentPreRunE(c *cobra.Command, _ []string) error {
	// Allow --root_path derivation if bootstrapping.
	if ca.RootPath == "" {
		bc, err := rotate.FromBootstrapContext(c.Context())
		if err == nil && bc.RootKeyCommonName != "" {
			ca.RootPath = fmt.Sprintf("%s.crt", bc.RootKeyCommonName)
		}
	}
	return multierr.Combine(cmd.MustBeNonempty("bucket", &ca.PrivateBucket),
		cmd.MustBeNonempty("root_path", &ca.RootPath),
		cmd.MustBeNonempty("cert_dir", &ca.SigningCertDirInGCS))
}

// InitContext modifies the keys.Context in ctx to use this implementation of the certificate
// authority interface.
func (ca *CertificateAuthority) InitContext(ctx context.Context) (context.Context, error) {
	c, err := keys.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	c.CA = ca
	return ctx, nil
}

// certificateAuthorityMutation represents a not-yet-finalized change to the CA persistent state.
type certificateAuthorityMutation struct {
	primaryRootVersion    *string
	primarySigningVersion *string
	certs                 map[string]*x509.Certificate
	rootCert              *x509.Certificate
}

// SetPrimarySigningKeyVersion updates the mutation to store a new primary root key version.
func (m *certificateAuthorityMutation) SetPrimaryRootKeyVersion(keyVersionName string) {
	m.primaryRootVersion = &keyVersionName
}

// SetPrimarySigningKeyVersion updates the mutation to store a new primary signing key version.
func (m *certificateAuthorityMutation) SetPrimarySigningKeyVersion(keyVersionName string) {
	m.primarySigningVersion = &keyVersionName
}

// AddSigningKeyCert updates the mutation to persist the given certificate and a record that it is
// for the given keyVersionName.
func (m *certificateAuthorityMutation) AddSigningKeyCert(keyVersionName string, cert *x509.Certificate) {
	if m.certs == nil {
		m.certs = make(map[string]*x509.Certificate)
	}
	m.certs[keyVersionName] = cert
}

func (m *certificateAuthorityMutation) SetRootKeyCert(cert *x509.Certificate) {
	m.rootCert = cert
}

// PrimaryRootKeyVersion returns the keyVersionName of the active root key.
func (ca *CertificateAuthority) PrimaryRootKeyVersion(ctx context.Context) (string, error) {
	manifest, err := ca.getManifest(ctx)
	if err != nil {
		return "", err
	}
	return manifest.GetPrimaryRootKeyVersionName(), nil
}

// PrimarySigningKeyVersion returns the keyVersionName of the active signing key.
func (ca *CertificateAuthority) PrimarySigningKeyVersion(ctx context.Context) (string, error) {
	manifest, err := ca.getManifest(ctx)
	if err != nil {
		return "", err
	}
	return manifest.GetPrimarySigningKeyVersionName(), nil
}

// Finalize persists the changes to the CA represented by the given mutation.
func (ca *CertificateAuthority) Finalize(ctx context.Context, m styp.CertificateAuthorityMutation) error {
	mut, ok := m.(*certificateAuthorityMutation)
	if !ok {
		return fmt.Errorf("expected gcsca mutation object, got %v", m)
	}
	manifest, err := ca.getManifest(ctx)
	if err != nil {
		return err
	}
	if mut.primaryRootVersion != nil {
		manifest.PrimaryRootKeyVersionName = *mut.primaryRootVersion
	}
	if mut.primarySigningVersion != nil {
		manifest.PrimarySigningKeyVersionName = *mut.primarySigningVersion
	}
	var wroteAny bool
	for keyVersionName, cert := range mut.certs {
		wrote, err := ca.upload(ctx, manifest, keyVersionName, cert)
		if err != nil {
			return fmt.Errorf("could not upload certificate for key %q: %w", keyVersionName, err)
		}
		wroteAny = wroteAny || wrote
	}

	// update the root cert if needed
	if mut.rootCert != nil {
		wrote, err := ca.writeIfAllowed(ctx, ca.RootPath, certPemBytes(mut.rootCert))
		if err != nil {
			return err
		}
		wroteAny = wroteAny || wrote
	}
	if wroteAny {
		return ca.writeManifest(ctx)
	}
	return nil
}

func (ca *CertificateAuthority) writeIfAllowed(ctx context.Context, path string, data []byte) (bool, error) {
	exists, err := ca.Storage.Exists(ctx, ca.PrivateBucket, path)
	if err != nil {
		return false, err
	}
	if exists && !output.AllowOverwrite(ctx) {
		if !output.AllowRecoverableError(ctx) {
			return false, status.Errorf(codes.AlreadyExists, "object %q exists, overwrite not enabled",
				path)
		}
		// Don't overwrite. Just keep going.
		return false, nil
	}
	return true, stops.WriteFile(ctx, ca.Storage, ca.PrivateBucket, path, data)
}

func (ca *CertificateAuthority) getManifest(ctx context.Context) (*cpb.GCECertificateManifest, error) {
	if ca.manifest != nil {
		return ca.manifest, nil
	}
	manifest, err := ca.readManifest(ctx)
	if err != nil {
		return nil, err
	}
	ca.manifest = manifest
	return manifest, nil
}

// Flush forces the next manifest use to read from storage.
func (ca *CertificateAuthority) Flush() {
	ca.manifest = nil
}

// NewMutation returns a new CertificateAuthorityMutation.
func (ca *CertificateAuthority) NewMutation() styp.CertificateAuthorityMutation {
	return &certificateAuthorityMutation{}
}

// readManifest returns the protobuf representation of the map of keyVersion name to object name.
func (ca *CertificateAuthority) readManifest(ctx context.Context) (*cpb.GCECertificateManifest, error) {
	r, err := ca.Storage.Reader(ctx, ca.PrivateBucket, ManifestObjectName)
	if ca.Storage.IsNotExists(err) {
		output.Warningf(ctx, "key certificate manifest %q wasn't found in bucket %q", ManifestObjectName, ca.PrivateBucket)
		return &cpb.GCECertificateManifest{}, nil
	} else if err != nil {
		return nil, fmt.Errorf("could not read manifest %q: %w", ManifestObjectName, err)
	}
	defer r.Close()
	text, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	result := &cpb.GCECertificateManifest{}
	if err := prototext.Unmarshal(text, result); err != nil {
		return nil, fmt.Errorf("could not unmarshal manifest: %w", err)
	}
	return result, nil
}

// writeManifest writes the current manifest state to the expected manifest object name in the
// staging bucket.
func (ca *CertificateAuthority) writeManifest(ctx context.Context) error {
	manifestBytes, err := prototext.MarshalOptions{Multiline: true}.Marshal(ca.manifest)
	if err != nil {
		return fmt.Errorf("could not marshal updated manifest: %v", err)
	}
	return stops.WriteFile(ctx, ca.Storage, ca.PrivateBucket, ManifestObjectName, manifestBytes)
}

// certPath returns the object_name of the certificate for a given keyVersionName as stored in the
// key manifest.
func (ca *CertificateAuthority) certPath(ctx context.Context, keyVersionName string) (string, error) {
	manifest, err := ca.getManifest(ctx)
	if err != nil {
		return "", err
	}
	entry := getEntry(manifest, keyVersionName)
	if entry == nil {
		return "", fmt.Errorf("key version %q does not have a certificate in the manifest",
			keyVersionName)
	}
	return entry.GetObjectPath(), nil
}

// Certificate returns the certificate for the named key in DER format.
func (ca *CertificateAuthority) Certificate(ctx context.Context, keyVersionName string) ([]byte, error) {
	path, err := ca.certPath(ctx, keyVersionName)
	if err != nil {
		return nil, err
	}
	content, err := stops.ReadFile(ctx, ca.Storage, ca.PrivateBucket, path)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(content)
	if err != nil {
		return nil, err
	}

	return cert.Raw, nil
}

// CABundle returns the intermediate..root certificate chain as consecutive PEM blocks for the
// signing key.
func (ca *CertificateAuthority) CABundle(ctx context.Context, keyVersionName string) ([]byte, error) {
	if !strings.HasPrefix(keyVersionName, ca.SigningKeyPrefix) {
		return nil, fmt.Errorf("key version %q does not have expected prefix %q", keyVersionName, ca.SigningKeyPrefix)
	}
	return stops.ReadFile(ctx, ca.Storage, ca.PrivateBucket, ca.RootPath)
}

func (ca *CertificateAuthority) certObjectName(cert *x509.Certificate) string {
	// Create the object name
	var dir string
	if ca.SigningCertDirInGCS != "" {
		dir = ca.SigningCertDirInGCS
		if !strings.HasSuffix(dir, "/") {
			dir += "/"
		}
	}
	// The certificate file path is its common name and serial number within the certs directory.
	return fmt.Sprintf("%s%s-%s.crt", dir, cert.Subject.CommonName, cert.Subject.SerialNumber)
}

func certPemBytes(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// upload uploads the given x.509 certificate for the named key to the GCS private bucket,
// and updates the given manifest to reflect the created object's entry. Returns whether any writes
// happened and any errors.
func (ca *CertificateAuthority) upload(ctx context.Context, manifest *cpb.GCECertificateManifest, keyVersionName string, cert *x509.Certificate) (bool, error) {
	entry := getEntry(manifest, keyVersionName)
	if entry != nil {
		if output.AllowRecoverableError(ctx) {
			return false, nil
		}
		if !output.AllowOverwrite(ctx) {
			return false, ErrKeyExists
		}
		output.Warningf(ctx, "key version exists in manifest %v -> %v", keyVersionName, entry.GetObjectPath())
	}
	name := ca.certObjectName(cert)
	// The non-root certificates are expected to be in DER format. See the CertificateAuthority
	// interface.
	wrote, err := ca.writeIfAllowed(ctx, name, cert.Raw)
	if err != nil {
		return false, err
	}
	// The key is fresh, so add it to the manifest.
	if entry == nil && wrote {
		entries := append(manifest.Entries, &cpb.GCECertificateManifest_Entry{
			KeyVersionName: keyVersionName,
			ObjectPath:     name,
		})
		manifest.Entries = entries
	}
	return wrote, nil
}

// getEntry returns the GCECertificateManifest_Entry whose key_version_name equals keyVersionName,
// or nil if no such entry exists.
func getEntry(manifest *cpb.GCECertificateManifest, keyVersionName string) *cpb.GCECertificateManifest_Entry {
	for _, entry := range manifest.Entries {
		if entry.KeyVersionName == keyVersionName {
			return entry
		}
	}
	return nil
}

// PrepareResources ensures all necessary resources are present for the CA to function. This is
// needed for bootstrapping. Specifically this ensures the storage bucket exists.
func (ca *CertificateAuthority) PrepareResources(ctx context.Context) error {
	return ca.Storage.EnsureBucketExists(ctx, ca.PrivateBucket)
}

// Wipeout deletes all files in the bucket.
func (ca *CertificateAuthority) Wipeout(ctx context.Context) error {
	ca.manifest = nil
	return ca.Storage.Wipeout(ctx, ca.PrivateBucket)
}
