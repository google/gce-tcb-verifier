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

package nonprod

import (
	"crypto/sha512"
	"fmt"
	"golang.org/x/net/context"
	"math/big"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/google/gce-tcb-verifier/cmd"
	"github.com/google/gce-tcb-verifier/cmd/output"
	"github.com/google/gce-tcb-verifier/endorse"
	"github.com/google/gce-tcb-verifier/keys"
	pb "github.com/google/gce-tcb-verifier/proto/endorsement"
	rpb "github.com/google/gce-tcb-verifier/proto/releases"
	"github.com/google/gce-tcb-verifier/rotate"
	"github.com/google/gce-tcb-verifier/sign/gcsca"
	"github.com/google/gce-tcb-verifier/sign/memca"
	"github.com/google/gce-tcb-verifier/sign/nonprod"
	"github.com/google/gce-tcb-verifier/testing/devkeys"
	"github.com/google/gce-tcb-verifier/testing/nonprod/localca"
	"github.com/google/gce-tcb-verifier/testing/nonprod/localkm"
	"github.com/google/gce-tcb-verifier/testing/nonprod/localnonvcs"
	"github.com/google/gce-tcb-verifier/testing/nonprod/memkm"
	"github.com/google/gce-tcb-verifier/testing/ovmfsev"
	"github.com/google/gce-tcb-verifier/testing/testkm"
	"github.com/google/gce-tcb-verifier/testing/testsign"
	"github.com/google/go-cmp/cmp"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

const mb = 1024 * 1024

var (
	fwBytes  = ovmfsev.CleanExample(&testing.T{}, 2*mb)
	fwDigest = sha512.Sum384(fwBytes)
)

func emptyManifest(t testing.TB, dir string) {
	if err := os.WriteFile(path.Join(dir, endorse.ManifestFile), []byte{}, 0666); err != nil {
		t.Fatal(err)
	}
}

func marshalManifest(manifest *rpb.VMEndorsementMap) []byte {
	out, _ := prototext.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(manifest)
	return out
}

func mkFirmware(t testing.TB, dir string) string {
	t.Helper()
	fwPath := path.Join(dir, "fw.fd")
	if err := os.WriteFile(fwPath, fwBytes, 0666); err != nil {
		t.Fatal(err)
	}
	return fwPath
}

type wants interface {
	check(ctx context.Context, ec *endorse.Context, cops endorse.ChangeOps) error
}

type wantSame struct {
	left  string
	right string
}

func (w *wantSame) check(ctx context.Context, ec *endorse.Context, cops endorse.ChangeOps) error {
	lpath := ec.VCS.ReleasePath(ctx, w.left)
	rpath := ec.VCS.ReleasePath(ctx, w.right)
	left, err := cops.ReadFile(ctx, lpath)
	if err != nil {
		return err
	}
	right, err := cops.ReadFile(ctx, rpath)
	if err != nil {
		return err
	}
	if diff := cmp.Diff(left, right); diff != "" {
		return fmt.Errorf("contents for %q %q unexpected (-got, +want): %s", lpath, rpath, diff)
	}
	return nil
}

type wantEndorsement struct {
	endorsementPath string
	clspec          uint64
}

func (w *wantEndorsement) check(ctx context.Context, ec *endorse.Context, cops endorse.ChangeOps) error {
	path := ec.VCS.ReleasePath(ctx, w.endorsementPath)
	e, err := cops.ReadFile(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to read endorsement %q: %v", w.endorsementPath, err)
	}
	endorsement := &pb.VMLaunchEndorsement{}
	if err := proto.Unmarshal(e, endorsement); err != nil {
		return fmt.Errorf("failed to unmarshal endorsement: %v", err)
	}
	golden := &pb.VMGoldenMeasurement{}
	if err := proto.Unmarshal(endorsement.SerializedUefiGolden, golden); err != nil {
		return fmt.Errorf("failed to unmarshal serialized uefi golden: %v", err)
	}
	if golden.ClSpec != w.clspec {
		return fmt.Errorf("got clspec %d, want %d", golden.ClSpec, w.clspec)
	}
	if len(endorsement.GetSignature()) == 0 {
		return fmt.Errorf("signature is empty")
	}
	return nil
}

type wantManifest struct {
	wantManifest *rpb.VMEndorsementMap
}

func (w *wantManifest) check(ctx context.Context, ec *endorse.Context, cops endorse.ChangeOps) error {
	path := ec.VCS.ReleasePath(ctx, path.Join(ec.OutDir, endorse.ManifestFile))
	e, err := cops.ReadFile(ctx, path)
	if err != nil {
		return err
	}
	manifest := &rpb.VMEndorsementMap{}
	if err := prototext.Unmarshal(e, manifest); err != nil {
		return fmt.Errorf("failed to unmarshal manifest (size %d) at %q: %v", len(e), path, err)
	}
	if d := cmp.Diff(manifest, w.wantManifest, protocmp.Transform()); d != "" {
		return fmt.Errorf("manifest differs from expectations:\n%s", d)
	}
	return nil
}

func simple(t testing.TB, app *cmd.AppComponents, getArgs func(fwPath, certdir string) []string, outdir string) {
	checkPath := path.Join(outdir, "endorsement.binarypb")
	simpleCmd(t, cmd.MakeApp(context.Background(), app), getArgs, &wantEndorsement{endorsementPath: checkPath})
}

func simpleCmd(t testing.TB, cmd *cobra.Command, getArgs func(fwPath, certdir string) []string, wants ...wants) {
	certdir := t.TempDir()
	emptyManifest(t, certdir)
	fwPath := path.Join(certdir, "fw.fd")
	mkFirmware(t, certdir)
	args := getArgs(fwPath, certdir)
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Errorf("%s resulted in %v, expected success", strings.Join(args, " "), err)
	}
	if err := os.Remove(fwPath); err != nil {
		t.Error(err)
	}
	eCmd, _, err := cmd.Find([]string{"endorse"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := eCmd.Context()
	ec, err := endorse.FromContext(ctx)
	if err != nil {
		t.Fatalf("Post-execute endorse context: %v", err)
	}
	cops, err := ec.VCS.GetChangeOps(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range wants {
		if err := want.check(ctx, ec, cops); err != nil {
			t.Fatal(err)
		}
	}
}

func memApp() *cmd.AppComponents {
	return &cmd.AppComponents{
		Endorse:   &localnonvcs.T{},
		Bootstrap: &cmd.PartialComponent{},
		Global: cmd.Compose(&memkm.T{Signer: &nonprod.Signer{Rand: testsign.RootRand()}},
			memca.Create()),
	}
}

func memAppBootstrapped() *cmd.AppComponents {
	app := memApp()
	app.Global = cmd.Compose(memca.TestOnlyCertificateAuthority(), memkm.TestOnlyT())
	return app
}

func memkmLocalca() *cmd.AppComponents {
	return &cmd.AppComponents{
		Endorse:   &localnonvcs.T{},
		Bootstrap: &cmd.PartialComponent{},
		Global: cmd.Compose(&memkm.T{Signer: &nonprod.Signer{Rand: testsign.RootRand()}},
			&localca.T{}),
	}
}

func memkmLocalcaBootstrapped() *cmd.AppComponents {
	app := memkmLocalca()
	app.Global = cmd.Compose(memkm.TestOnlyT(), &localca.T{})
	return app
}

func localkmMemca() *cmd.AppComponents {
	return &cmd.AppComponents{
		Endorse:   &localnonvcs.T{},
		Bootstrap: &cmd.PartialComponent{},
		Global: cmd.Compose(&localkm.T{T: memkm.T{Signer: &nonprod.Signer{Rand: testsign.RootRand()}}},
			memca.Create()),
	}
}

func localkmMemcaBootstrapped() *cmd.AppComponents {
	app := localkmMemca()
	app.Global = cmd.Compose(
		&localkm.T{T: memkm.T{Signer: &nonprod.Signer{Rand: testsign.RootRand()}}},
		memca.TestOnlyCertificateAuthority())
	return app
}

func TestEndorseRootCmd(t *testing.T) {
	outdir := t.TempDir()
	outdir2 := t.TempDir()
	simpleCmd(t, RootCmd, func(fwPath, certdir string) []string {
		keyDir := t.TempDir()
		if err := devkeys.DumpTo(&devkeys.Options{
			KeyDir:   keyDir,
			CertRoot: certdir,
			CertDir:  "signer_certs",
			Bucket:   "certs-dev",
		}); err != nil {
			t.Fatal(err)
		}
		return []string{"endorse", "--add_snp", "--uefi", fwPath, "--verbose",
			"--key_dir", keyDir,
			"--root_path", "root.crt",
			"--bucket_root", certdir,
			"--out_root", outdir,
			"--snapshot_dir", outdir2,
		}
	}, &wantEndorsement{
		endorsementPath: path.Join(outdir2, "fw.fd.signed"),
		clspec:          123,
	})
}

func TestEndorseLocalKeysMemca(t *testing.T) {
	outdir := t.TempDir()
	simple(t, memAppBootstrapped(), func(fwPath, certdir string) []string {
		keyDir := t.TempDir()
		if err := devkeys.DumpTo(&devkeys.Options{
			KeyDir:   keyDir,
			CertRoot: certdir,
			CertDir:  "certs",
			Bucket:   "testbucket",
		}); err != nil {
			t.Fatal(err)
		}
		return []string{"endorse", "--add_snp", "--uefi", fwPath, "--verbose", "--out_root", outdir}
	}, "")
}

// When the release branch already exists from a previous release candidate, there are some
// scenarios with existing files that need coverage.
func TestEndorseLocalKeysMemcaWithExistingBranch(t *testing.T) {
	legacyWant := &wantEndorsement{endorsementPath: "2023-09-26-T20-00-viperlite-npi-2-RC00.binarypb"}
	tcs := []struct {
		name         string
		initialFiles []*endorse.File
		extraArgs    []string
		wantErr      string
		wants        []wants
	}{
		{
			name:  "empty",
			wants: []wants{legacyWant},
		},
		{
			name: "manifest exists but irrelevant",
			initialFiles: []*endorse.File{
				&endorse.File{
					Path: "manifest.textproto",
					Contents: []byte(`
					# proto-file: github.com/google/gce-tcb-verifier/proto/releases.proto
					# proto-message: VMEndorsementMap
					# !!! THIS FILE WAS AUTOMATICALLY GENERATED !!!
					# !!! DO NOT MODIFY BY HAND !!!
					entries {
						digest: "nothindoin"
						path: "irrelevant.binarypb"
						create_time: {
							seconds: 5
							nanos: 100
						}
					}
`),
				},
			},
			wants: []wants{legacyWant},
		},
		{
			name:      "manifest exists with different path for digest",
			extraArgs: []string{"--timestamp=2023-11-10T16:13:00Z"},
			initialFiles: []*endorse.File{
				{
					Path: "manifest.textproto",
					Contents: marshalManifest(&rpb.VMEndorsementMap{
						Entries: []*rpb.VMEndorsementMap_Entry{
							&rpb.VMEndorsementMap_Entry{
								Digest:     []byte(`not the firmware digest`),
								Path:       "irrelevant1.binarypb",
								CreateTime: &timestamppb.Timestamp{},
							},
							&rpb.VMEndorsementMap_Entry{
								Digest:     fwDigest[:],
								Path:       "irrelevant2.binarypb",
								CreateTime: &timestamppb.Timestamp{},
							},
						},
					}),
				},
			},
			wants: []wants{legacyWant, &wantManifest{
				wantManifest: &rpb.VMEndorsementMap{
					Entries: []*rpb.VMEndorsementMap_Entry{
						&rpb.VMEndorsementMap_Entry{
							Digest:     []byte(`not the firmware digest`),
							Path:       "irrelevant1.binarypb",
							CreateTime: &timestamppb.Timestamp{},
						},
						&rpb.VMEndorsementMap_Entry{
							Digest:     fwDigest[:],
							Path:       "2023-09-26-T20-00-viperlite-npi-2-RC00.binarypb",
							CreateTime: &timestamppb.Timestamp{Seconds: 1699632780, Nanos: 0},
						},
					},
				}}},
		},
		{
			name:      "manifest exists with same path for different digest",
			extraArgs: []string{"--overwrite", "--timestamp=2023-11-10T16:13:00Z"},
			initialFiles: []*endorse.File{
				{
					Path: "manifest.textproto",
					Contents: marshalManifest(&rpb.VMEndorsementMap{
						Entries: []*rpb.VMEndorsementMap_Entry{
							&rpb.VMEndorsementMap_Entry{
								Digest:     []byte(`not the firmware digest`),
								Path:       "2023-09-26-T20-00-viperlite-npi-2-RC00.binarypb",
								CreateTime: &timestamppb.Timestamp{},
							},
						},
					}),
				},
				{
					Path:     "2023-09-26-T20-00-viperlite-npi-2-RC00.binarypb",
					Contents: []byte(`stuff`),
				},
			},
			wants: []wants{legacyWant, &wantManifest{
				wantManifest: &rpb.VMEndorsementMap{
					Entries: []*rpb.VMEndorsementMap_Entry{
						&rpb.VMEndorsementMap_Entry{
							Digest:     fwDigest[:],
							Path:       "2023-09-26-T20-00-viperlite-npi-2-RC00.binarypb",
							CreateTime: &timestamppb.Timestamp{Seconds: 1699632780, Nanos: 0},
						},
					},
				}}},
		},
		{
			name:      "manifest exists with same path for same digest",
			extraArgs: []string{"--overwrite", "--timestamp=2023-11-10T16:13:00Z"},
			initialFiles: []*endorse.File{
				{
					Path: "manifest.textproto",
					Contents: marshalManifest(&rpb.VMEndorsementMap{
						Entries: []*rpb.VMEndorsementMap_Entry{
							&rpb.VMEndorsementMap_Entry{
								Digest:     fwDigest[:],
								Path:       "2023-09-26-T20-00-viperlite-npi-2-RC00.binarypb",
								CreateTime: &timestamppb.Timestamp{Seconds: 1, Nanos: 100},
							},
						},
					}),
				},
				{
					Path:     "2023-09-26-T20-00-viperlite-npi-2-RC00.binarypb",
					Contents: []byte(`stuff`),
				},
			},
			wants: []wants{legacyWant, &wantManifest{wantManifest: &rpb.VMEndorsementMap{
				Entries: []*rpb.VMEndorsementMap_Entry{
					&rpb.VMEndorsementMap_Entry{
						Digest:     fwDigest[:],
						Path:       "2023-09-26-T20-00-viperlite-npi-2-RC00.binarypb",
						CreateTime: &timestamppb.Timestamp{Seconds: 1699632780, Nanos: 0},
					},
				},
			}}},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			outdir := t.TempDir()
			simpleCmd(t, cmd.MakeApp(context.Background(), memAppBootstrapped()),
				func(fwPath, certdir string) []string {
					keyDir := t.TempDir()
					if err := devkeys.DumpTo(&devkeys.Options{
						KeyDir:   keyDir,
						CertRoot: certdir,
						CertDir:  "certs",
						Bucket:   "testbucket",
					}); err != nil {
						t.Fatal(err)
					}
					for _, f := range tc.initialFiles {
						outpath := path.Join(outdir, f.Path)
						if err := os.WriteFile(outpath, f.Contents, 0755); err != nil {
							t.Fatalf("could not initialize file %q: %v", outpath, err)
						}
					}
					return append([]string{"endorse", "--add_snp", "--uefi", fwPath, "--verbose",
						"--out_root", outdir,
						"--candidate_name", "2023-09-26-T20-00-viperlite-npi-2-RC00",
						"--release_branch", "cloud-cluster-vm_release_branch/568701730.21"}, tc.extraArgs...)
				}, tc.wants...)
		})
	}
}

func TestEndorseSimpleLocalCA(t *testing.T) {
	outdir := t.TempDir()
	cmd := memkmLocalcaBootstrapped()
	simple(t, cmd, func(fwPath, certdir string) []string {
		keyDir := t.TempDir()
		if err := devkeys.DumpTo(&devkeys.Options{
			KeyDir:   keyDir,
			CertRoot: certdir,
			CertDir:  "certs",
			Bucket:   "testbucket",
		}); err != nil {
			t.Fatal(err)
		}
		return []string{"endorse", "--add_snp", "--uefi", fwPath, "--verbose",
			"--bucket_root", certdir,
			"--root_path", "root.crt",
			"--bucket", "testbucket",
			"--cert_dir", "certs",
			"--out_root", outdir,
		}
	}, "")

	if _, err := os.ReadFile(path.Join(outdir, "endorsement.binarypb")); err != nil {
		t.Fatal(err)
	}
}

func TestEndorseDevkeys(t *testing.T) {
	simple(t, memAppBootstrapped(), func(fwPath, _ string) []string {
		return []string{"endorse", "--add_snp", "--uefi", fwPath, "--verbose", "--out_root", t.TempDir()}
	}, "")
}

func TestEndorseDevkeysFromFile(t *testing.T) {
	outdir := t.TempDir()
	if err := os.Mkdir(path.Join(outdir, "bar"), 0755); err != nil {
		t.Fatal(err)
	}

	simple(t, localkmMemcaBootstrapped(), func(fwPath, certdir string) []string {
		t.Helper()
		keyDir := t.TempDir()
		if err := devkeys.DumpTo(&devkeys.Options{
			KeyDir:   keyDir,
			CertRoot: certdir,
			CertDir:  "signer_certs",
			Bucket:   "testbucket",
		}); err != nil {
			t.Fatal(err)
		}
		return []string{"endorse", "--add_snp", "--uefi", fwPath, "--out_dir", "bar", "--verbose",
			"--key_dir", keyDir,
			"--out_root", outdir,
		}
	}, "bar")
}

func TestFlagValidation(t *testing.T) {
	tcs := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "no --uefi fails",
			args: []string{"endorse", "--root_path=root.crt"},
			want: "expected --uefi path",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			// A new rootCmd is needed for a new instance of flags.
			rootCmd := cmd.MakeApp(context.Background(), memkmLocalcaBootstrapped())
			certdir := t.TempDir()
			emptyManifest(t, certdir)
			rootCmd.SetArgs(append(tc.args, "--out_dir", t.TempDir()))
			err := rootCmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("`%s` errored unexpectedly: %v, want %q", strings.Join(tc.args, " "), err, tc.want)
			}
		})
	}
}

func TestRootPathDerivation(t *testing.T) {
	tcs := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "root_path derivation works on bootstrap",
			args: []string{"bootstrap"},
			want: "GCE-cc-tcb-root.crt",
		},
		{
			name: "root_path derivation defers to the flag",
			args: []string{"bootstrap", "--root_key_cn=ignored", "--root_path=rot.crt"},
			want: "rot.crt",
		},
		{
			name: "root_path derivation uses root_key_cn",
			args: []string{"bootstrap", "--root_key_cn=woot"},
			want: "woot.crt",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			// A new rootCmd is needed for a new instance of flags.
			app := memkmLocalcaBootstrapped()
			app.Bootstrap = &cmd.PartialComponent{
				FInitContext: func(ctx context.Context) (context.Context, error) {
					c, err := keys.FromContext(ctx)
					if err != nil {
						return ctx, err
					}
					ca, ok := c.CA.(*gcsca.CertificateAuthority)
					if !ok {
						return nil, fmt.Errorf("got CA of type %T, want gcsca.CertificateAuthority", c.CA)
					}
					if ca.RootPath != tc.want {
						return nil, fmt.Errorf("contextual root_path=%q, want %q", ca.RootPath, tc.want)
					}
					return ctx, nil
				},
			}
			rootCmd := cmd.MakeApp(context.Background(), app)
			certdir := t.TempDir()
			emptyManifest(t, certdir)
			opts := &devkeys.Options{
				Bucket: "foobucket", CertRoot: t.TempDir(), CertDir: "signer_certs", KeyDir: t.TempDir(),
			}
			if err := devkeys.DumpTo(opts); err != nil {
				t.Fatal(err)
			}
			args := append(tc.args, "--bucket=foobucket", "--bucket_root", opts.CertRoot, "--cert_dir",
				opts.CertDir)
			rootCmd.SetArgs(args)
			err := rootCmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("`%s` errored unexpectedly: %v, want %q", strings.Join(tc.args, " "), err, tc.want)
			}
		})
	}
}

func TestNextSerial(t *testing.T) {
	tcs := []struct {
		name string
		args []string
		want *big.Int
	}{
		{
			name: "default is dev signing key serial (2) + 1",
			want: big.NewInt(3),
		},
		{
			name: "setting signing key serial gives expected value",
			args: []string{"--rotated_key_serial_override", "98765432123456789123456789"},
			want: func() *big.Int {
				z := new(big.Int)
				z.SetString("98765432123456789123456789", 10)
				return z
			}(),
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cmp := cmd.Compose(memkm.TestOnlyT(), memca.TestOnlyCertificateAuthority(), &cmd.RotateCommand{})
			c := &cobra.Command{
				PersistentPreRunE: cmp.PersistentPreRunE,
				RunE: cmd.ComposeRun(cmp, func(ctx context.Context) error {
					skc, err := rotate.FromSigningKeyContext(ctx)
					if err != nil {
						return err
					}
					if skc.SigningKeySerial.Cmp(tc.want) != 0 {
						return fmt.Errorf("next serial number is %v, want %v", skc.SigningKeySerial, tc.want)
					}
					return nil
				}),
			}
			c.SetContext(keys.NewContext(context.Background(), &keys.Context{}))
			cmp.AddFlags(c)
			c.SetArgs(tc.args)
			if err := c.Execute(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRootOptionContext(t *testing.T) {
	checkCtx := func(ctx context.Context) {
		t.Helper()
		if _, err := output.FromContext(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Ensure that we're always getting the quiet/verbose flags baked into the context.
	rootCmd := cmd.MakeApp(context.Background(), memAppBootstrapped())
	checkCtx(rootCmd.Context())
	eCmd, _, err := rootCmd.Find([]string{"endorse"})
	if err != nil {
		t.Fatal(err)
	}
	checkCtx(eCmd.Context())
}

func TestBootstrapCmd(t *testing.T) {
	tcs := []struct {
		name string
		app  *cmd.AppComponents
		opts *testkm.Options
	}{
		{
			name: "memkm memca",
			app:  memApp(),
			opts: &testkm.Options{},
		},
		{
			name: "memkm localca",
			app:  memkmLocalca(),
			opts: &testkm.Options{CA: testkm.TestLocalca},
		},
		{
			name: "localkm memca",
			app:  localkmMemca(),
			opts: &testkm.Options{KM: testkm.TestLocalkm},
		},
		{
			name: "localkm localca",
			app:  localApp(),
			opts: &testkm.Options{KM: testkm.TestLocalkm, CA: testkm.TestLocalca},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			testkm.BootstrapCmd(t, cmd.MakeApp(context.Background(), tc.app), tc.opts)
		})
	}
}

func TestWipeoutCmd(t *testing.T) {
	tcs := []struct {
		name string
		app  *cmd.AppComponents
		opts *testkm.Options
	}{
		{
			name: "memkm memca",
			app:  memApp(),
			opts: &testkm.Options{},
		},
		{
			name: "memkm localca",
			app:  memkmLocalca(),
			opts: &testkm.Options{CA: testkm.TestLocalca},
		},
		{
			name: "localkm memca",
			app:  localkmMemca(),
			opts: &testkm.Options{KM: testkm.TestLocalkm},
		},
		{
			name: "localkm localca",
			app:  localApp(),
			opts: &testkm.Options{KM: testkm.TestLocalkm, CA: testkm.TestLocalca},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			testkm.WipeoutCmd(t, cmd.MakeApp(context.Background(), tc.app), tc.opts)
		})
	}
}
