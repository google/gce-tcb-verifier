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

// Package devkeys provides test-only pregenerated and signed root and signer keys.
package devkeys

import (
	"os"
	"path"

	pb "github.com/google/gce-tcb-verifier/proto/certificates"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/encoding/prototext"

	_ "embed"
)

var (
	// RootPEM contains a PEM-encoded private key generated by the bootstrapping process.
	//go:embed root.pem
	RootPEM []byte

	// RootCert contains a DER-encoded x509 certificate of RootPEM, self-signed as a CA.
	//go:embed root.crt
	RootCert []byte

	// PrimarySigningKeyPEM contains a PEM-encoded private key for signing binaries, generated by the
	// bootstrapping process.
	//go:embed primarySigningKey.pem
	PrimarySigningKeyPEM []byte

	// PrimarySigningKeyCert contains a DER-encoded root-signed x509 certificate for the signer key.
	//go:embed primarySigningKey.crt
	PrimarySigningKeyCert []byte

	// KeyManifest contains a textproto manifest with paths to and names of the root and primary keys,
	// and their certs.
	//go:embed keyManifest.textproto
	KeyManifest []byte
)

// Options provides parameters to where to write dev keys and certificate files, and how to populate
// the keyManifest.textproto.
type Options struct {
	KeyDir                       string
	CertRoot                     string
	CertDir                      string
	Bucket                       string
	RootKeyVersionName           string
	PrimarySigningKeyVersionName string
}

func retargetKeyManifest(opts *Options) ([]byte, error) {
	manifest := &pb.GCECertificateManifest{}
	prototext.Unmarshal(KeyManifest, manifest)
	// Swap out "signer_certs" directory with opts.CertDir, and key version names if specified.
	if opts.RootKeyVersionName != "" {
		manifest.PrimaryRootKeyVersionName = opts.RootKeyVersionName
	}
	if opts.PrimarySigningKeyVersionName != "" {
		manifest.PrimarySigningKeyVersionName = opts.PrimarySigningKeyVersionName
	}
	for _, entry := range manifest.Entries {
		isRoot := entry.KeyVersionName == "root"
		if opts.RootKeyVersionName != "" && isRoot {
			entry.KeyVersionName = opts.RootKeyVersionName
		}
		// The root key certificate is at root_path, so it's not retargeted.
		if isRoot {
			continue
		}
		if opts.PrimarySigningKeyVersionName != "" && entry.KeyVersionName == "primarySigningKey" {
			entry.KeyVersionName = opts.PrimarySigningKeyVersionName
		}
		entry.ObjectPath = path.Join(opts.CertDir, path.Base(entry.GetObjectPath()))
	}
	result, err := prototext.MarshalOptions{Multiline: true}.Marshal(manifest)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// DumpTo writes the embedded files to a directory so they can be used for tests that need file
// paths.
func DumpTo(opts *Options) error {
	if err := os.MkdirAll(path.Join(opts.CertRoot, opts.Bucket, opts.CertDir), 0755); err != nil {
		return err
	}
	manifest, err := retargetKeyManifest(opts)
	if err != nil {
		return err
	}
	rootPEM := path.Join(opts.KeyDir, "root.pem")
	primarySigningKeyPEM := path.Join(opts.KeyDir, "primarySigningKey.pem")
	keyManifest := path.Join(opts.CertRoot, opts.Bucket, "keyManifest.textproto")
	rootCert := path.Join(opts.CertRoot, opts.Bucket, "root.crt")
	primarySigningKeyCert := path.Join(opts.CertRoot, opts.Bucket, opts.CertDir, "primarySigningKey.crt")
	return multierr.Combine(os.WriteFile(keyManifest, manifest, 0644),
		os.WriteFile(rootPEM, RootPEM, 0644),
		os.WriteFile(rootCert, RootCert, 0644),
		os.WriteFile(primarySigningKeyPEM, PrimarySigningKeyPEM, 0644),
		os.WriteFile(primarySigningKeyCert, PrimarySigningKeyCert, 0644))
}
