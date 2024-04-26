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

// Package localkm provides a keys.ManagerInterface implementation that persists keys to disk.
package localkm

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/google/gce-tcb-verifier/keys"
	"github.com/google/gce-tcb-verifier/sign/nonprod"
	"github.com/google/gce-tcb-verifier/testing/nonprod/memkm"
	"github.com/spf13/cobra"
)

const (
	extension = ".pem"
)

// T is a local key manager that persists private keys to a given directory in .pem format. Slashes
// in keyversionnames disallowed. The file name without .pem is synonymous with the keyversionname.
type T struct {
	memkm.T
	KeyDir    string
	FileToKvn map[string]string
	kvnToFile map[string]string
}

func loadKey(signer *nonprod.Signer, keyVersionName, path string) error {
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file %q: %w", path, err)
	}
	block, rest := pem.Decode(contents)
	if block == nil || len(rest) != 0 {
		return fmt.Errorf("failed to decode file %q as a single PRIVATE KEY pem", path)
	}
	var key any
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PRIVATE KEY pem: %w", err)
		}
		err = signer.LoadKey(keyVersionName, key)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA PRIVATE KEY pem: %w", err)
		}
		err = signer.LoadKey(keyVersionName, key)
	default:
		return fmt.Errorf("unexpected pem type %q", block.Type)
	}
	if err != nil {
		return fmt.Errorf("failed to load key %q: %w", keyVersionName, err)
	}
	return nil
}

func (k *T) foreachKey(ctx context.Context, f func(context.Context, string) error) error {
	entries, err := os.ReadDir(k.KeyDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), extension) {
			continue
		}
		keyVersionName := strings.TrimSuffix(entry.Name(), extension)
		if k.FileToKvn != nil { // Apply file to keyVersionName renamings if defined.
			if kvn, ok := k.FileToKvn[keyVersionName]; ok {
				keyVersionName = kvn
			}
		}
		if err := f(ctx, keyVersionName); err != nil {
			return err
		}
	}
	return nil
}

func (k *T) keyPath(keyVersionName string) string {
	fileName := keyVersionName
	if k.kvnToFile != nil {
		if file, ok := k.kvnToFile[keyVersionName]; ok {
			fileName = file
		}
	}
	return path.Join(k.KeyDir, fileName+extension)
}

// Init initializes a local key manager given its KeyDir, signature randomness and signer
// randomness with all the keys in KeyDir.
func (k *T) Init(context.Context) error {
	if k.FileToKvn != nil {
		k.kvnToFile = make(map[string]string)
		for file, kvn := range k.FileToKvn {
			k.kvnToFile[kvn] = file
		}
	}
	return k.foreachKey(context.Background(), func(_ context.Context, keyVersionName string) error {
		return loadKey(k.Signer, keyVersionName, k.keyPath(keyVersionName))
	})
}

func (k *T) saveKey(keyVersionName string, key any) error {
	contents, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal PRIVATE KEY pem: %w", err)
	}
	p := k.keyPath(keyVersionName)
	b := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: contents,
	}
	w, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return fmt.Errorf("failed to create file %q: %w", p, err)
	}
	defer w.Close()
	return pem.Encode(w, b)
}

// CreateFirstSigningKey is called during CA bootstrapping to create the first signing key that
// can be used for endorse.
func (k *T) CreateFirstSigningKey(ctx context.Context) (string, error) {
	keyVersionName, err := k.T.CreateFirstSigningKey(ctx)
	if err != nil {
		return "", err
	}
	if err := k.saveKey(keyVersionName, k.T.Signer.Keys[keyVersionName]); err != nil {
		return "", err
	}

	return keyVersionName, nil
}

// CreateNewSigningKeyVersion is callable after CreateNewSigningKey, and is meant for key
// rotation. The signing key's name ought to be available from the context.
func (k *T) CreateNewSigningKeyVersion(ctx context.Context) (string, error) {
	keyVersionName, err := k.T.CreateNewSigningKeyVersion(ctx)
	if err != nil {
		return "", err
	}
	if err := k.saveKey(keyVersionName, k.T.Signer.Keys[keyVersionName]); err != nil {
		return "", err
	}
	return keyVersionName, nil
}

// CreateNewRootKey establishes a new key for use as the root CA key.
func (k *T) CreateNewRootKey(ctx context.Context) (string, error) {
	keyVersionName, err := k.T.CreateNewRootKey(ctx)
	if err != nil {
		return "", err
	}
	if err := k.saveKey(keyVersionName, k.T.Signer.Keys[keyVersionName]); err != nil {
		return "", err
	}
	return keyVersionName, nil
}

// DestroyKeyVersion destroys a single key version.
func (k *T) DestroyKeyVersion(ctx context.Context, keyVersionName string) error {
	_ = k.T.DestroyKeyVersion(ctx, keyVersionName) // known nil
	return os.Remove(path.Join(k.KeyDir, keyVersionName+extension))
}

// Wipeout destroys all keys managed by this manager, which is understood as all .pem files in
// KeyDir.
func (k *T) Wipeout(ctx context.Context) error {
	_ = k.T.Wipeout(ctx) // known nil
	return k.foreachKey(ctx, k.DestroyKeyVersion)
}

// InitContext extends the given context with whatever else the component needs before execution.
func (k *T) InitContext(ctx context.Context) (context.Context, error) {
	// KeyDir ought to be populated by now, so load its keys.
	if err := k.Init(ctx); err != nil {
		return nil, err
	}
	ctx1, err := k.T.InitContext(ctx)
	if err != nil {
		return nil, err
	}
	// Override memkm's Manager setting with our own.
	c, err := keys.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	c.Manager = k
	return ctx1, nil
}

// AddFlags adds any implementation-specific flags for this command component.
func (k *T) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&k.KeyDir, "key_dir", "private_keys",
		"The directory in which to read and write private key material.")
}

// PersistentPreRunE returns an error if the results of the parsed flags constitute an error.
func (k *T) PersistentPreRunE(*cobra.Command, []string) error {
	info, err := os.Stat(k.KeyDir)
	if err != nil {
		return fmt.Errorf("failed to stat %q: %w", k.KeyDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("key_dir %q is not a directory", k.KeyDir)
	}
	return nil
}
