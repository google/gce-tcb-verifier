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

package localca

import (
	"golang.org/x/net/context"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/google/gce-tcb-verifier/cmd/output"
	"github.com/google/gce-tcb-verifier/keys"
	cpb "github.com/google/gce-tcb-verifier/proto/certificates"
	"github.com/google/gce-tcb-verifier/sign/gcsca"
	styp "github.com/google/gce-tcb-verifier/sign/types"
	"github.com/google/gce-tcb-verifier/testing/devkeys"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/gce-tcb-verifier/testing/storage"
	"github.com/google/gce-tcb-verifier/testing/testca"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/prototext"
)

func overwriteArgs(t testing.TB) []string {
	return append(fullArgs(t), "--overwrite")
}

func phasedArgs(phase int, bucket string) func(t testing.TB) []string {
	return func(t testing.TB) []string {
		certDir := t.TempDir()
		manifestPath := path.Join(certDir, bucket, gcsca.ManifestObjectName)
		primaryKeyObject := path.Join("signer_certs", "primarySigningKey.crt")
		primaryKeyPath := path.Join(certDir, bucket, primaryKeyObject)
		if err := os.MkdirAll(path.Dir(primaryKeyPath), 0755); err != nil {
			t.Fatalf("os.MkdirAll %q failed: %v", path.Dir(primaryKeyPath), err)
		}
		manifest := &cpb.GCECertificateManifest{}
		if phase > 1 {
			manifest.PrimaryRootKeyVersionName = "root"
		}
		if phase > 2 {
			manifest.PrimarySigningKeyVersionName = "primarySigningKey"
		}
		if phase > 3 {
			rootPath := path.Join(certDir, bucket, "root.crt")
			if err := os.WriteFile(rootPath, devkeys.RootCert, 0644); err != nil {
				t.Fatalf("os.WriteFile %q failed: %v", rootPath, err)
			}
		}
		if phase > 4 {
			manifest.Entries = []*cpb.GCECertificateManifest_Entry{
				&cpb.GCECertificateManifest_Entry{
					KeyVersionName: "primarySigningKey",
					ObjectPath:     primaryKeyObject,
				},
			}
		}
		if phase > 5 {
			if err := os.WriteFile(primaryKeyPath, devkeys.PrimarySigningKeyCert, 0644); err != nil {
				t.Fatalf("os.WriteFile %q failed: %v", primaryKeyPath, err)
			}
		}
		if phase > 0 {
			manifestytes, err := prototext.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(manifest)
			if err != nil {
				t.Fatalf("prototext.Marshal failed: %v", err)
			}
			if err := os.WriteFile(manifestPath, manifestytes, 0644); err != nil {
				t.Fatalf("os.WriteFile %q failed: %v", manifestPath, err)
			}
		}
		return []string{
			"--bucket_root", certDir,
			"--bucket", bucket,
			"--root_path=root.crt",
		}
	}
}

func fullArgs(t testing.TB) []string {
	return phasedArgs(6, ".")(t)
}

func create(t testing.TB, getArgs func(testing.TB) []string) (context.Context, styp.CertificateAuthority, error) {
	t.Helper()
	ctx0 := context.Background()
	opts := &output.Options{}
	ctx1 := output.NewContext(keys.NewContext(ctx0, &keys.Context{}), opts)

	component := &T{}
	cmd := &cobra.Command{
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := component.InitContext(cmd.Context())
			return err
		},
		PersistentPreRunE: component.PersistentPreRunE,
	}
	component.AddFlags(cmd)
	opts.AddFlags(cmd)
	cmd.SetArgs(getArgs(t))
	err := cmd.ExecuteContext(ctx1)
	return ctx1, component.CA, err
}

func TestSetGetRootName(t *testing.T) {
	ctx, ca, err := create(t, overwriteArgs)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	testca.SetGetRootName(ctx, t, ca)
}

func TestSetGetPrimarySigningKeyName(t *testing.T) {
	ctx, ca, err := create(t, overwriteArgs)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	testca.SetGetPrimarySigningKeyName(ctx, t, ca)
}

func TestSetGetRootCert(t *testing.T) {
	ctx, ca, err := create(t, overwriteArgs)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	testca.SetGetRootCert(ctx, t, ca)
}

func TestAddSigningKeyCert(t *testing.T) {
	ctx, ca, err := create(t, overwriteArgs)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	testca.AddGetSigningKeyCert(ctx, t, ca)
}

func TestWipeout(t *testing.T) {
	ctx, ca, err := create(t, overwriteArgs)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	testca.Wipeout(ctx, t, ca)
}

func TestBadInitContext(t *testing.T) {
	component := &T{CA: &gcsca.CertificateAuthority{Storage: &storage.Mock{}}}
	wantErr := "does not use local storage"
	if _, err := component.InitContext(context.Background()); err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("component.InitContext(_) = %v, want error to contain %q", err, wantErr)
	}
}

func TestMissingData(t *testing.T) {
	tcs := []struct {
		name    string
		getArgs func(t testing.TB) []string
		wantErr string
	}{
		{
			name:    "manifest",
			getArgs: fullArgs,
		},
		{
			name:    "nothing",
			getArgs: phasedArgs(0, "bukkit"),
			wantErr: "root key version not set. Run bootstrap first",
		},
		{
			name:    "just manifest",
			getArgs: phasedArgs(1, "bukkit"),
			wantErr: "root key version not set. Run bootstrap first",
		},
		{
			name:    "just root",
			getArgs: phasedArgs(2, "bukkit"),
			wantErr: "primary signing key version not set. Run bootstrap first",
		},
		{
			name:    "root and primary, no certs",
			getArgs: phasedArgs(3, "bukkit"),
			wantErr: "could not fetch CA bundle",
		},
		{
			name:    "root and primary, ca bundle, no primary entry",
			getArgs: phasedArgs(4, "bukkit"),
			wantErr: "key version \"primarySigningKey\" does not have a certificate in the manifest",
		},
		{
			name:    "root and primary, ca bundle, primary entry",
			getArgs: phasedArgs(5, "."),
			wantErr: "file \"./signer_certs/primarySigningKey.crt\" does not exist",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := create(t, tc.getArgs); !match.Error(err, tc.wantErr) {
				t.Fatalf("ExecuteContext(_) = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
