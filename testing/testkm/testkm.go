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

// Package testkm provides reusable test cases for in-memory and local file key managers, since they
// both use the same underlying signer.
package testkm

import (
	"context"
	"crypto/x509"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/google/gce-tcb-verifier/keys"
	"github.com/google/gce-tcb-verifier/rotate"
	sops "github.com/google/gce-tcb-verifier/sign/ops"
	"github.com/google/gce-tcb-verifier/testing/devkeys"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/spf13/cobra"
)

func checkPostBootstrap(ctx context.Context, t *testing.T) {
	t.Helper()
	c, err := keys.FromContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.CA == nil {
		t.Fatal(keys.ErrNoCertificateAuthority)
	}

	rootName, err := c.CA.PrimaryRootKeyVersion(ctx)
	if err != nil || rootName == "" {
		t.Errorf("no primary root key version post-bootstrap: %v", err)
	}
	signer, err := c.CA.PrimarySigningKeyVersion(ctx)
	if err != nil || signer == "" {
		t.Errorf("no primary signing key version post-bootstrap: %v", err)
	}
	if _, err := sops.IssuerCertFromBundle(ctx, c.CA, rootName); err != nil {
		t.Errorf("no root cert: %v", err)
	}
	if b, err := c.CA.Certificate(ctx, signer); err != nil || len(b) == 0 {
		t.Errorf("no primarySigningKey certificate post-bootstrap: %v", err)
	}
}

// Bootstrap tests correctness properties of key chain bootstrapping from the keys.Context fields.
func Bootstrap(ctx0 context.Context, t *testing.T) {
	t.Helper()
	now := time.Now()
	ctx := rotate.NewBootstrapContext(ctx0, &rotate.BootstrapContext{
		RootKeyCommonName:    "rootCn",
		RootKeySerial:        big.NewInt(1),
		SigningKeyCommonName: "signingKeyCn",
		SigningKeySerial:     big.NewInt(2),
		Now:                  now,
	})
	if err := rotate.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap operation failed: %v", err)
	}
	checkPostBootstrap(ctx, t)
}

// KeyEnum represents which key manager implementation will be tested.
type KeyEnum int

// CAEnum represents which CA implementation will be tested.
type CAEnum int

const (
	// TestMemkm represents testing with a memkm.Manager
	TestMemkm KeyEnum = iota
	// TestLocalkm represents testing with a localkm.T
	TestLocalkm
	// TestFakeKms represents testing with a gcpkms.Manager connected to a fake KMS server.
	TestFakeKms
)

const (
	// TestMemca represents testing with a memca.CertificateAuthority
	TestMemca CAEnum = iota
	// TestLocalca represents testing with a gcsca.CertificateAuthority using a local filesystem
	// storage client.
	TestLocalca
	// TestFakeGcsca represents testing with a gcsca.CertificateAuthority using a fake storage client.
	TestFakeGcsca
)

// Options provides test tuning depending on the command specialization.
type Options struct {
	KM                           KeyEnum
	CA                           CAEnum
	RootKeyVersionName           string
	PrimarySigningKeyVersionName string
	ExtraArgs                    []string
	WantErr                      string
}

func (opts *Options) addArgs(t testing.TB, args []string) ([]string, error) {
	keyDir := t.TempDir()
	certRoot := t.TempDir()
	if err := devkeys.DumpTo(&devkeys.Options{
		KeyDir:                       keyDir,
		CertRoot:                     certRoot,
		CertDir:                      "certs",
		Bucket:                       "testbuck",
		RootKeyVersionName:           opts.RootKeyVersionName,
		PrimarySigningKeyVersionName: opts.PrimarySigningKeyVersionName,
	}); err != nil {
		return nil, err
	}
	if opts.KM == TestLocalkm {
		args = append(args, "--key_dir", keyDir)
	}
	if opts.CA == TestLocalca {
		args = append(args, "--bucket_root", certRoot, "--root_path", "root.crt")
	}
	if opts.CA == TestFakeGcsca || opts.CA == TestLocalca {
		args = append(args, "--bucket=testbuck")
	}
	// The local versions are preloaded with devkeys which will need to be overwritten.
	if opts.KM == TestLocalkm || opts.CA == TestLocalca {
		args = append(args, "--overwrite")
	}
	return append(args, opts.ExtraArgs...), nil
}

func checkRun(cmd *cobra.Command, opName string, opts *Options) error {
	var wantErr string
	if opts != nil {
		wantErr = opts.WantErr
	}
	if err := cmd.Execute(); !match.Error(err, wantErr) {
		return fmt.Errorf("%s operation result %v did not match the expected %q", opName, err, wantErr)
	}
	return nil
}

// BootstrapCmd tests correctness properties of key chain bootstrapping from a given root command.
func BootstrapCmd(t *testing.T, command *cobra.Command, opts *Options) {
	t.Helper()
	now := time.Now()
	args, err := opts.addArgs(t, []string{
		"bootstrap", "--root_key_cn=rootCn", "--signing_key_cn=signingKeyCn",
		"--root_key_serial=1", "--initial_signing_key_serial=2", "--timestamp", now.Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	command.SetArgs(args)
	if err := checkRun(command, "bootstrap", opts); err != nil {
		t.Fatal(err)
	}
	bCmd, _, err := command.Find([]string{"bootstrap"})
	if err != nil {
		t.Fatal(err)
	}

	if opts != nil && opts.WantErr == "" {
		checkPostBootstrap(bCmd.Context(), t)
	}
}

func checkPostRotate(ctx context.Context, t *testing.T, original, wantRotatedName, wantCn string) {
	c, err := keys.FromContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rotatedName, err := c.CA.PrimarySigningKeyVersion(ctx)
	if err != nil || rotatedName == "" {
		t.Errorf("no primary signing key version post-rotate: %v", err)
	}
	if rotatedName != wantRotatedName {
		t.Errorf("rotatedName = %q, want %q", rotatedName, wantRotatedName)
	}
	b, err := c.CA.Certificate(ctx, wantRotatedName)
	if err != nil || len(b) == 0 {
		t.Errorf("no %s certificate post-rotate", wantRotatedName)
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		t.Fatalf("failed to parse rotated key's certificate: %v", err)
	}
	if cert.Subject.CommonName != wantCn {
		t.Errorf("rotated cert subject's common name = %q, want %q", cert.Subject.CommonName, wantCn)
	}
	if _, err := c.Signer.PublicKey(ctx, original); err == nil {
		t.Errorf("original %q not destroyed", original)
	}
}

// Rotate tests correctness properties of key rotation from the keys.Cont,t fields. It expects a
// that the manager is already configured with root and primary signing key.
func Rotate(ctx0 context.Context, t *testing.T, wantRotatedName string) {
	t.Helper()
	wantCn := "rotatedCn"
	c, err := keys.FromContext(ctx0)
	if err != nil {
		t.Fatal(err)
	}
	original, err := c.CA.PrimarySigningKeyVersion(ctx0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ctx := rotate.NewSigningKeyContext(ctx0, &rotate.SigningKeyContext{
		SigningKeyCommonName: wantCn,
		SigningKeySerial:     big.NewInt(2),
		Now:                  now,
	})
	if _, err := rotate.Key(ctx); err != nil {
		t.Fatal(err)
	}
	checkPostRotate(ctx, t, original, wantRotatedName, wantCn)
}

// RotateCmd tests correctness properties of key rotation from a command. It expects the command's
// context to already be configured with root and primary signing key.
func RotateCmd(t *testing.T, cmd *cobra.Command, originalName, wantRotatedName, wantCn string, opts *Options) {
	t.Helper()
	args, err := opts.addArgs(t, []string{
		"rotate", "--signing_key_cn", wantCn, "--rotated_key_serial_override=3",
		"--timestamp", time.Now().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	cmd.SetArgs(args)
	rCmd, _, err := cmd.Find([]string{"rotate"})
	if err != nil {
		t.Fatal(err)
	}

	if err := checkRun(cmd, "rotate", opts); err != nil {
		t.Fatal(err)
	}

	if opts != nil && opts.WantErr == "" {
		checkPostRotate(rCmd.Context(), t, originalName, wantRotatedName, wantCn)
	}
}

// PostWipeoutProperties tests post-Wipeout correctness properties of a CA in the keys.Context in
// the context.
func PostWipeoutProperties(ctx context.Context, t testing.TB, opts *Options) {
	t.Helper()
	c, err := keys.FromContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.CA == nil {
		t.Fatal(keys.ErrNoCertificateAuthority)
	}
	rootName := "root"
	primarySigningKeyName := "primarySigningKey"
	if opts != nil && opts.RootKeyVersionName != "" {
		rootName = opts.RootKeyVersionName
	}
	if opts != nil && opts.PrimarySigningKeyVersionName != "" {
		primarySigningKeyName = opts.PrimarySigningKeyVersionName
	}
	if _, err := sops.IssuerCertFromBundle(ctx, c.CA, rootName); err == nil {
		t.Errorf("wipeout left %q cert intact", rootName)
	}
	if _, err := c.CA.Certificate(ctx, primarySigningKeyName); err == nil {
		t.Errorf("wipeout left %q cert intact", primarySigningKeyName)
	}
	if _, err := c.Signer.PublicKey(ctx, rootName); err == nil {
		t.Errorf("wipeout left %q intact", rootName)
	}
	if _, err := c.Signer.PublicKey(ctx, primarySigningKeyName); err == nil {
		t.Errorf("wipeout left %q intact", primarySigningKeyName)
	}
}

// Wipeout tests correctness properties of a bootstrap followed by a wipeout, purely from the
// keys.Context fields by interface.
func Wipeout(ctx0 context.Context, t *testing.T) {
	t.Helper()
	now := time.Now()
	ctx := rotate.NewBootstrapContext(ctx0, &rotate.BootstrapContext{
		RootKeyCommonName:    "rootCn",
		RootKeySerial:        big.NewInt(1),
		SigningKeyCommonName: "signingKeyCn",
		SigningKeySerial:     big.NewInt(2),
		Now:                  now,
	})
	if err := rotate.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if err := rotate.Wipeout(ctx); err != nil {
		t.Fatal(err)
	}
	PostWipeoutProperties(ctx, t, nil)
}

// WipeoutCmd tests correctness properties of key+CA wipeout from a command. It is intended to
// be used on a command whose command context is already configured with keys and certs.
func WipeoutCmd(t *testing.T, cmd *cobra.Command, opts *Options) {
	t.Helper()
	args, err := opts.addArgs(t, []string{"wipeout"})
	if err != nil {
		t.Fatal(err)
	}
	cmd.SetArgs(args)
	wCmd, _, err := cmd.Find([]string{"wipeout"})
	if err != nil {
		t.Fatal(err)
	}

	if err := checkRun(cmd, "wipeout", opts); err != nil {
		t.Fatal(err)
	}

	if opts != nil && opts.WantErr == "" {
		PostWipeoutProperties(wCmd.Context(), t, opts)
	}
}
