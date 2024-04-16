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

// Package localca is a local storage CommandComponent instantiation of gcsca.
//
// This implementation of CA expects the key manager to be a localkm, since some flag behaviors need
// to be validated across the two.
package localca

import (
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"os"
	"path"

	"github.com/google/gce-tcb-verifier/cmd/output"
	"github.com/google/gce-tcb-verifier/keys"
	"github.com/google/gce-tcb-verifier/sign/gcsca"
	sops "github.com/google/gce-tcb-verifier/sign/ops"
	"github.com/google/gce-tcb-verifier/storage/local"
	"github.com/spf13/cobra"
)

var errNoLocalStorage = errors.New("internal: localca's CA object does not use local storage")

// T is the localca certificate authority type.
type T struct {
	CA *gcsca.CertificateAuthority
}

func (ca *T) checkCerts(ctx context.Context) error {
	if ca.CA == nil {
		return keys.ErrNoCertificateAuthority
	}
	rootKeyVersionName, err := ca.CA.PrimaryRootKeyVersion(ctx)
	if err != nil {
		return err
	}
	if rootKeyVersionName == "" {
		return errors.New("root key version not set. Run bootstrap first")
	}
	primarySigningKeyVersionName, err := ca.CA.PrimarySigningKeyVersion(ctx)
	if err != nil {
		return err
	}
	if primarySigningKeyVersionName == "" {
		return errors.New("primary signing key version not set. Run bootstrap first")
	}

	if _, err = sops.IssuerCertFromBundle(ctx, ca.CA, rootKeyVersionName); err != nil {
		return err
	}
	_, err = ca.CA.Certificate(ctx, primarySigningKeyVersionName)
	return err
}

// InitContext extends the given context with whatever else the component needs before execution.
func (ca *T) InitContext(ctx context.Context) (context.Context, error) {
	sto, ok := ca.CA.Storage.(*local.StorageClient)
	if !ok {
		return nil, errNoLocalStorage
	}
	certsPath := path.Join(sto.Root, ca.CA.SigningCertDirInGCS)
	if err := os.Mkdir(certsPath, 0755); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("failed to create %q: %v", certsPath, err)
	}
	if err := ca.checkCerts(ctx); err != nil {
		return nil, err
	}
	return ca.CA.InitContext(ctx)
}

// AddFlags adds any implementation-specific flags for this command component.
func (ca *T) AddFlags(c *cobra.Command) {
	if ca.CA == nil {
		ca.CA = &gcsca.CertificateAuthority{Storage: &local.StorageClient{}}
	}
	if _, ok := ca.CA.Storage.(*local.StorageClient); !ok {
		output.Errorf(c.Context(), "internal: localca storage is %T, want local.StorageClient",
			ca.CA.Storage)
	}
	c.PersistentFlags().StringVar(&ca.CA.Storage.(*local.StorageClient).Root, "bucket_root", "",
		"Path to the local filesystem directory that contains the CA \"bucket\" directory.")
	ca.CA.AddFlags(c)
}

// PersistentPreRunE returns an error if the results of the parsed flags constitute an error.
func (ca *T) PersistentPreRunE(cmd *cobra.Command, args []string) error {
	return ca.CA.PersistentPreRunE(cmd, args)
}
