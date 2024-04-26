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

package localkm

import (
	"context"
	"crypto/rsa" // test-only for parsing in nonprod key manager.
	"crypto/x509"
	"encoding/pem"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/google/gce-tcb-verifier/cmd"
	"github.com/google/gce-tcb-verifier/keys"
	"github.com/google/gce-tcb-verifier/sign/memca"
	"github.com/google/gce-tcb-verifier/sign/nonprod"
	"github.com/google/gce-tcb-verifier/testing/devkeys"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/gce-tcb-verifier/testing/nonprod/memkm"
	"github.com/google/gce-tcb-verifier/testing/testkm"
	"github.com/google/gce-tcb-verifier/testing/testsign"
	"github.com/spf13/cobra"
)

func readyManager(ctx0 context.Context, t testing.TB, args []string) (*T, context.Context) {
	t.Helper()
	m := &T{T: memkm.T{Signer: &nonprod.Signer{Rand: testsign.RootRand()}}}
	cmd := &cobra.Command{}
	cmd.SetContext(keys.NewContext(ctx0, &keys.Context{}))

	m.AddFlags(cmd)
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("ParseFlags() = %v, want nil", err)
	}
	if err := m.Init(cmd.Context()); err != nil {
		t.Fatalf("%v.Init(ctx) = %v, want nil", m, err)
	}
	return m, cmd.Context()
}

func TestBootstrap(t *testing.T) {
	ctx0 := context.Background()
	keyDir := t.TempDir()
	m, ctx1 := readyManager(ctx0, t, []string{"--key_dir", keyDir})
	ctx, err := cmd.ComposeInitContext(ctx1, m, memca.Create())
	if err != nil {
		t.Fatalf("ComposeInitContext(_, m, memca) = %v, want nil", err)
	}
	testkm.Bootstrap(ctx, t)
	if _, err := os.Stat(path.Join(keyDir, "root.pem")); err != nil {
		t.Fatalf("localkm Bootstrap() did not create root.pem: %v", err)
	}
}

func TestRotate(t *testing.T) {
	ctx0 := context.Background()
	keyDir := t.TempDir()
	m, ctx1 := readyManager(ctx0, t, []string{"--key_dir", keyDir})
	ctx, err := cmd.ComposeInitContext(ctx1, m, memca.Create())
	if err != nil {
		t.Fatalf("ComposeInitContext(_, %v, memca) = %v, want nil", m, err)
	}
	testkm.Bootstrap(ctx, t)
	testkm.Rotate(ctx, t, "primarySigningKey_1")
	if _, err := os.Stat(path.Join(keyDir, "primarySigningKey_1.pem")); err != nil {
		t.Fatalf("localkm Rotate() did not create primarySigningKey_1.pem: %v", err)
	}
}

func TestWipeout(t *testing.T) {
	ctx0 := context.Background()
	keyDir := t.TempDir()
	m, ctx1 := readyManager(ctx0, t, []string{"--key_dir", keyDir})
	ctx, err := cmd.ComposeInitContext(ctx1, m, memca.Create())
	if err != nil {
		t.Fatalf("ComposeInitContext(_, %v, memca) = %v, want nil", m, err)
	}
	testkm.Wipeout(ctx, t)
	if _, err := os.Stat(path.Join(keyDir, "root.pem")); err == nil {
		t.Fatalf("localkm Wipeout() did not delete root.pem")
	}
}

func TestBadSaveKey(t *testing.T) {
	keyDir := t.TempDir()
	m := &T{
		T:      memkm.T{Signer: &nonprod.Signer{Rand: testsign.RootRand()}},
		KeyDir: keyDir,
	}
	if err := m.Init(context.Background()); err != nil {
		t.Fatalf("%v.Init(_) = %v, want nil", m, err)
	}
	wantBadKeyErr := "failed to marshal"
	if err := m.saveKey("foo", nil); err == nil || !strings.Contains(err.Error(), wantBadKeyErr) {
		t.Fatalf("saveKey() = %v, want error to contain %q", err, wantBadKeyErr)
	}
}

func TestBadSaveKeyDir(t *testing.T) {
	signer := &nonprod.Signer{Rand: testsign.RootRand()}
	key, err := signer.GenerateRootKey("foo")
	if err != nil {
		t.Fatalf("GenerateRootKey() = %v, want nil", err)
	}
	m := &T{T: memkm.T{Signer: signer}, KeyDir: "certainly_doesnt_exist"}
	wantBadKeyErr := "failed to create file"
	if err := m.saveKey("foo", key); err == nil || !strings.Contains(err.Error(), wantBadKeyErr) {
		t.Fatalf("saveKey() = %v, want error to contain %q", err, wantBadKeyErr)
	}
}

func TestLoadKeys(t *testing.T) {
	dir := t.TempDir()
	// These devkeys use BEGIN PRIVATE KEY
	if err := devkeys.DumpTo(&devkeys.Options{
		KeyDir:   dir,
		CertRoot: dir,
		CertDir:  "certdev",
		Bucket:   "bucket",
	}); err != nil {
		t.Fatalf("devkeys.DumpTo(%q) = _, %v, want nil", dir, err)
	}
	// make subdirectories for test cases.
	for _, md := range []string{"noread", "badpem", "badprivateder", "badrsader", "goodrsader"} {
		casedir := path.Join(dir, md)
		if err := os.Mkdir(casedir, 0755); err != nil {
			t.Fatalf("os.Mkdir(%q, 0755) = %v, want nil", casedir, err)
		}
	}

	// Translate the root key to PKCS1 for testing that pathway.
	b, _ := pem.Decode(devkeys.RootPEM)
	root, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		t.Fatalf("x509.ParsePKCS8PrivateKey(%q) = _, %v, want nil", b.Bytes, err)
	}
	rbs := x509.MarshalPKCS1PrivateKey(root.(*rsa.PrivateKey))
	if err := os.WriteFile(path.Join(dir, "goodrsader", "root.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: rbs}), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q, _, 0644) = _, %v, want nil", b.Bytes, err)
	}
	nokey := path.Join(dir, "noread", "nope.pem")
	if err := os.WriteFile(nokey, []byte(`bar`), 0200); err != nil {
		t.Fatalf("os.WriteFile(%q, 0200) = _, %v, want nil", nokey, err)
	}
	badpem := path.Join(dir, "badpem", "nope.pem")
	if err := os.WriteFile(badpem, []byte(`bar`), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q, 0644) = _, %v, want nil", badpem, err)
	}
	badprivateder := path.Join(dir, "badprivateder", "priv.pem")
	if err := os.WriteFile(badprivateder,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte(`qux`)}), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q, 0644) = _, %v, want nil", badprivateder, err)
	}
	badrsader := path.Join(dir, "badrsader", "nope.pem")
	if err := os.WriteFile(badrsader,
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte(`qux`)}), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q, 0644) = _, %v, want nil", badrsader, err)
	}

	// Make sure we don't try to ReadDir a non-dir.
	baddir := path.Join(dir, "not_a_dir")
	if err := os.WriteFile(baddir, []byte(`foo`), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q, _, 0644) = _, %v, want nil", baddir, err)
	}
	tcs := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name: "happy path",
			args: []string{"--key_dir", dir},
		},
		{
			name:    "missing --key_dir",
			args:    []string{},
			wantErr: "failed to stat",
		},
		{
			name:    "bad --key_dir",
			args:    []string{"--key_dir", baddir},
			wantErr: "not a directory",
		},
		{
			name:    "bad key in dir",
			args:    []string{"--key_dir", path.Join(dir, "noread")},
			wantErr: "failed to read",
		},
		{
			name: "good rsa key",
			args: []string{"--key_dir", path.Join(dir, "goodrsader")},
		},
		{
			name:    "bad pem",
			args:    []string{"--key_dir", path.Join(dir, "badpem")},
			wantErr: "failed to decode",
		},
		{
			name:    "bad pkcs8 der",
			args:    []string{"--key_dir", path.Join(dir, "badprivateder")},
			wantErr: "failed to parse PRIVATE KEY pem",
		},
		{
			name:    "bad pkcs1 der",
			args:    []string{"--key_dir", path.Join(dir, "badrsader")},
			wantErr: "failed to parse RSA PRIVATE KEY pem",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			m := &T{T: memkm.T{Signer: &nonprod.Signer{Rand: testsign.RootRand()}}}
			k := &cobra.Command{
				PersistentPreRunE: m.PersistentPreRunE,
				RunE: func(c *cobra.Command, _ []string) error {
					_, err := m.InitContext(c.Context())
					return err
				},
			}
			k.SetContext(keys.NewContext(context.Background(), &keys.Context{}))
			m.AddFlags(k)
			k.SetArgs(tc.args)
			if err := k.Execute(); !match.Error(err, tc.wantErr) {
				t.Fatalf("k.Execute() = %v, want %q", err, tc.wantErr)
			}
			// All happy paths define the "root" key version name, so confirm its existence.
			if tc.wantErr == "" {
				if _, err := m.T.Signer.PublicKey(k.Context(), "root"); err != nil {
					t.Fatalf("m.T.Signer.PublicKey(k.Context(), \"root\") = _, %v, want nil", err)
				}
			}
		})
	}
}
