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

package cmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/gce-tcb-verifier/extract"
	"github.com/google/gce-tcb-verifier/gcetcbendorsement"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/gce-tcb-verifier/sev"
	"github.com/google/gce-tcb-verifier/testing/devkeys"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/gce-tcb-verifier/verify/verifytest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-sev-guest/abi"
	labi "github.com/google/go-sev-guest/client/linuxabi"
	cpb "github.com/google/go-sev-guest/proto/check"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	test "github.com/google/go-sev-guest/testing"
	testclient "github.com/google/go-sev-guest/testing/client"
	"github.com/google/go-sev-guest/verify/trust"
	tcpb "github.com/google/go-tdx-guest/proto/checkconfig"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	mu                  sync.Once
	qp                  extract.LeveledQuoteProvider
	getter              trust.HTTPSGetter
	rootlessGetter      trust.HTTPSGetter
	now                 time.Time
	goodSnpQuote        []byte
	fakeEndorsement     []byte
	cleanSnpMeasurement []byte
	cleanTdxMeasurement []byte
)

const measurementOffset = 0x90

type ioResult struct {
	createWriter gcetcbendorsement.TerminalWriter
	createDefer  func()
	createErr    error
	writeErr     error
	readErr      error
	readBytes    []byte
	isTerminal   bool
}

type testIO struct {
	files map[string]*ioResult
}

type failWriter struct{}

var errInvalidWrite = errors.New("invalid write")

func (failWriter) Write(b []byte) (int, error) { return 0, errInvalidWrite }
func (failWriter) IsTerminal() bool            { return false }

type writeTo struct {
	buf        *bytes.Buffer
	dest       *[]byte
	isTerminal bool
}

func (w *writeTo) Write(b []byte) (int, error) {
	return w.buf.Write(b)
}

func (w *writeTo) IsTerminal() bool {
	return w.isTerminal
}

func (w *writeTo) cleanup() {
	*w.dest = w.buf.Bytes()
}

// Normal creation will write into readBytes.
func normalCreate(isTerminal bool) *ioResult {
	result := &ioResult{}
	wt := &writeTo{buf: bytes.NewBufferString(""), dest: &result.readBytes, isTerminal: isTerminal}
	result.createWriter = wt
	result.createDefer = wt.cleanup
	return result
}

func (t *testIO) Create(output string) (gcetcbendorsement.TerminalWriter, func(), error) {
	result, ok := t.files[output]
	if !ok {
		if t.files == nil {
			t.files = make(map[string]*ioResult)
		}
		result = normalCreate(output == "-")
		t.files[output] = result
	}
	return result.createWriter, result.createDefer, result.createErr
}

func (t *testIO) ReadFile(path string) ([]byte, error) {
	result, ok := t.files[path]
	if !ok {
		return nil, fmt.Errorf("file %q not found", path)
	}
	return result.readBytes, result.readErr
}

type tcquoteLevel struct {
	qp extract.QuoteProvider
}

func (qp *tcquoteLevel) IsSupported() bool {
	return qp.IsSupported()
}

func (qp *tcquoteLevel) GetRawQuoteAtLevel(reportData [64]byte, _ uint) ([]byte, error) {
	return qp.qp.GetRawQuote(reportData)
}

func initQuote(t testing.TB) func() {
	return func() {
		now = time.Now()
		fakeEndorsement = verifytest.FakeEndorsement(t)
		b := &test.AmdSignerBuilder{
			Extras: map[string][]byte{sev.GCEFwCertGUID: fakeEndorsement},
		}
		s, err := b.TestOnlyCertChain()
		if err != nil {
			t.Fatalf("b.TestOnlyCertChain() failed: %v", err)
		}
		var zeros [abi.ReportDataSize]byte
		var zeroRaw [labi.SnpReportRespReportSize]byte
		wantSnpMeas, err := hex.DecodeString(verifytest.CleanExampleMeasurement)
		if err != nil {
			t.Fatalf("hex.DecodeString(CleanExampleMeasurement) failed: %v", err)
		}
		wantTdxMeas, err := hex.DecodeString(verifytest.CleanTdxExampleMeasurement)
		if err != nil {
			t.Fatalf("hex.DecodeString(CleanExampleTdxMeasurement) failed: %v", err)
		}
		cleanSnpMeasurement = wantSnpMeas
		cleanTdxMeasurement = wantTdxMeas
		// Set Version to 2
		binary.LittleEndian.PutUint32(zeroRaw[0x00:0x04], 2)
		binary.LittleEndian.PutUint64(zeroRaw[0x08:0x10], abi.SnpPolicyToBytes(abi.SnpPolicy{}))
		// Signature algorithm ECC P-384 with SHA-384 is encoded as 1.
		binary.LittleEndian.PutUint32(zeroRaw[0x34:0x38], 1)
		// Write the expected measurement.
		copy(zeroRaw[measurementOffset:measurementOffset+abi.MeasurementSize], wantSnpMeas)
		qp0, _, _, _ := testclient.GetSevQuoteProvider([]test.TestCase{
			{
				Name:   "zeros",
				Input:  zeros,
				Output: zeroRaw,
			},
		}, &test.DeviceOptions{
			Product: &spb.SevProduct{Name: spb.SevProduct_SEV_PRODUCT_MILAN},
			Signer:  s,
			Now:     now,
		}, t)
		qp = &tcquoteLevel{qp: qp0}
		goodSnpQuote, err = qp0.GetRawQuote(zeros)
		if err != nil {
			t.Fatalf("qp.GetRawQuote() failed: %v", err)
		}
		getter = &test.Getter{
			Responses: map[string][]test.GetResponse{
				verifytest.CleanExampleURL:       []test.GetResponse{{Body: fakeEndorsement}},
				gcetcbendorsement.DefaultRootURL: []test.GetResponse{{Body: devkeys.RootCert}},
			},
		}
		rootlessGetter = &test.Getter{
			Responses: map[string][]test.GetResponse{
				verifytest.CleanExampleURL: []test.GetResponse{{Body: fakeEndorsement}},
			},
		}
	}
}

func TestExtract(t *testing.T) {
	mu.Do(initQuote(t))
	binAttestationPath := "attestation.bin"
	tcs := []struct {
		name    string
		input   []string
		qp      extract.LeveledQuoteProvider
		io      *testIO
		outpath string
		wantErr string
	}{
		{
			name:    "fail missing attestation",
			qp:      qp,
			input:   []string{binAttestationPath},
			io:      &testIO{},
			wantErr: "failed to read attestation file",
		},
		{
			name:    "fail too many arguments",
			input:   []string{"a", "b"},
			wantErr: "extract expects at most one argument, got 2",
		},
		{
			name:  "success no attestation good provider",
			qp:    qp,
			input: []string{},
			io:    &testIO{},
		},
		{
			name:  "success bad attestation good provider",
			qp:    qp,
			input: []string{binAttestationPath},
			io: &testIO{files: map[string]*ioResult{
				binAttestationPath: &ioResult{readBytes: []byte{0xc0, 0xde}}}},
		},
		{
			name:  "success good attestation no provider",
			input: []string{binAttestationPath, "--out", "endo.binarypb"},
			io: &testIO{files: map[string]*ioResult{
				binAttestationPath: &ioResult{readBytes: goodSnpQuote},
			}},
			outpath: "endo.binarypb",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			c := MakeRoot(context.WithValue(context.Background(), backendKey, &Backend{
				Provider: tc.qp,
				Getter:   getter,
				Now:      now,
				IO:       tc.io,
			}))
			c.SetArgs(append([]string{"extract"}, tc.input...))
			if err := c.Execute(); !match.Error(err, tc.wantErr) {
				t.Fatalf("extract %q errored unexpectedly. Got %v, want %q", binAttestationPath, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			path := "endorsement.binarypb"
			if tc.outpath != "" {
				path = tc.outpath
			}
			got, err := tc.io.ReadFile(path)
			if err != nil {
				t.Fatalf("tio.ReadFile(%q) failed: %v", path, err)
			}
			want := fakeEndorsement
			if !bytes.Equal(got, want) {
				t.Fatalf("extract %q = %v. Want %v", binAttestationPath, got, want)
			}
		})
	}
}

func TestInspect(t *testing.T) {
	mu.Do(initQuote(t))
	tcs := []struct {
		name    string
		input   []string
		io      *testIO
		want    []byte
		outloc  string
		wantErr string
	}{
		{
			name:  "mask success",
			input: []string{"mask", "endo.bin", "--path", "commit"},
			io: &testIO{
				files: map[string]*ioResult{
					"endo.bin": &ioResult{readBytes: func() []byte {
						out, _ := proto.Marshal(&epb.VMLaunchEndorsement{
							SerializedUefiGolden: func() []byte {
								out, _ := proto.Marshal(&epb.VMGoldenMeasurement{
									Commit: []byte{0xc0, 0xde},
								})
								return out
							}(),
						})
						return out
					}()},
				},
			},
			want: []byte("wN4="),
		},
		{
			name:  "mask success non-tty",
			input: []string{"mask", "endo.bin", "--path", "commit", "--out", "other"},
			io: &testIO{
				files: map[string]*ioResult{
					"endo.bin": &ioResult{readBytes: func() []byte {
						out, _ := proto.Marshal(&epb.VMLaunchEndorsement{
							SerializedUefiGolden: func() []byte {
								out, _ := proto.Marshal(&epb.VMGoldenMeasurement{
									Commit: []byte{0xc0, 0xde},
								})
								return out
							}(),
						})
						return out
					}()},
				},
			},
			outloc: "other",
			want:   []byte{0xc0, 0xde},
		},
		{
			name:  "payload success",
			input: []string{"payload", "endo.bin", "--bytesform", "hex"},
			io: &testIO{
				files: map[string]*ioResult{
					"endo.bin": &ioResult{readBytes: func() []byte {
						out, _ := proto.Marshal(&epb.VMLaunchEndorsement{
							SerializedUefiGolden: []byte{0xc0, 0xde},
						})
						return out
					}()},
				},
			},
			want: []byte("c0de"),
		},
		{
			name:  "signature success",
			input: []string{"signature", "endo.bin", "--bytesform", "hex"},
			io: &testIO{
				files: map[string]*ioResult{
					"endo.bin": &ioResult{readBytes: func() []byte {
						out, _ := proto.Marshal(&epb.VMLaunchEndorsement{
							Signature: []byte{0xc0, 0xde},
						})
						return out
					}()},
				},
			},
			want: []byte("c0de"),
		},
		{
			name:    "need argument",
			wantErr: "inspect expects exactly one argument, got 0",
		},
		{
			name:    "need 1 argument",
			wantErr: "inspect expects exactly one argument, got 2",
			input:   []string{"pos0", "pos1"},
		},
		{
			name:    "bytesform fail",
			wantErr: "failed to parse bytes form \"what\"",
			input:   []string{"ignore", "--bytesform", "what"},
		},
		{
			name:    "read fail",
			input:   []string{"dne"},
			io:      &testIO{},
			wantErr: "failed to read file",
		},
		{
			name:  "unmarshal fail",
			input: []string{"bad"},
			io: &testIO{files: map[string]*ioResult{
				"bad": &ioResult{readBytes: []byte{0xc0, 0xde}}}},
			wantErr: "failed to unmarshal proto *endorsement.VMLaunchEndorsement file",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			c := MakeRoot(context.WithValue(context.Background(), backendKey, &Backend{
				Provider: qp,
				Getter:   getter,
				Now:      now,
				IO:       tc.io,
			}))
			c.SetArgs(append([]string{"inspect"}, tc.input...))
			if err := c.Execute(); !match.Error(err, tc.wantErr) {
				t.Fatalf("inspect %s errored unexpectedly. Got %v. Want %q.", strings.Join(tc.input, " "), err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			toread := "-"
			if tc.outloc != "" {
				toread = tc.outloc
			}
			out, err := tc.io.ReadFile(toread)
			if err != nil {
				t.Fatalf("tc.io.ReadFile(%q) failed: %v", toread, err)
			}
			if !bytes.Equal(out, tc.want) {
				t.Fatalf("inspect %s = %v. Want %v", strings.Join(tc.input, " "), out, tc.want)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	mu.Do(initQuote(t))
	rootPath := "root.pem"
	endorsementPath := "endorsement.binarypb"
	tcs := []struct {
		name    string
		input   []string
		getter  trust.HTTPSGetter
		io      *testIO
		wantErr string
		want    []byte
	}{
		{
			name:  "success",
			input: []string{endorsementPath, "--root_cert", rootPath},
			io: &testIO{
				files: map[string]*ioResult{
					rootPath:        &ioResult{readBytes: devkeys.RootCert},
					endorsementPath: &ioResult{readBytes: fakeEndorsement},
				},
			},
		},
		{
			name:   "rootless success",
			getter: getter,
			input:  []string{endorsementPath},
			io: &testIO{
				files: map[string]*ioResult{
					endorsementPath: &ioResult{readBytes: fakeEndorsement},
				},
			},
		},
		{
			name:   "bad root file",
			input:  []string{endorsementPath, "--root_cert", rootPath},
			getter: getter,
			io: &testIO{
				files: map[string]*ioResult{
					endorsementPath: &ioResult{readBytes: fakeEndorsement},
				},
			},
			wantErr: "failed to get root certificate",
		},
		{
			name:   "bad root contents",
			input:  []string{endorsementPath, "--root_cert", rootPath},
			getter: getter,
			io: &testIO{
				files: map[string]*ioResult{
					rootPath:        &ioResult{readBytes: []byte("bad")},
					endorsementPath: &ioResult{readBytes: fakeEndorsement},
				},
			},
			wantErr: "failed to parse root certificate",
		},
		{
			name:   "rootless failure",
			input:  []string{endorsementPath},
			getter: rootlessGetter,
			io: &testIO{
				files: map[string]*ioResult{
					endorsementPath: &ioResult{readBytes: fakeEndorsement},
				},
			},
			wantErr: "failed to get root certificate",
		},
		{
			name:   "show curl",
			input:  []string{"FILE.binarypb", "--show"},
			io:     &testIO{},
			getter: getter,
			want: []byte(fmt.Sprintf(`openssl verify -CAfile <(openssl x509 -outform pem -in <(curl https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt)) \
  <(%s inspect mask "FILE.binarypb" --path=cert) \
&& \
openssl pkeyutl -verify -pkeyopt rsa_padding_mode:pss \
  -pkeyopt rsa_pss_saltlen:32 -pkeyopt digest:sha256 -pkeyopt rsa_mgf1_md:sha256 -pubin \
  -inkey <(openssl x509 -pubkey -nocert -outform pem -in <(%s inspect mask "FILE.binarypb" --path=cert)) \
  -sigfile <(%s inspect signature "FILE.binarypb") -keyform PEM \
  -in <(openssl dgst -sha256 -binary <(%s inspect payload "FILE.binarypb"))
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])),
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			c := MakeRoot(context.WithValue(context.Background(), backendKey, &Backend{
				Provider: qp,
				Getter:   tc.getter,
				Now:      now,
				IO:       tc.io,
			}))
			c.SetArgs(append([]string{"verify"}, tc.input...))
			if err := c.Execute(); !match.Error(err, tc.wantErr) {
				t.Fatalf("verify %s errored unexpectedly. Got %v. Want %q", strings.Join(tc.input, " "), err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			out, err := tc.io.ReadFile("-")
			if err != nil && len(tc.want) > 0 {
				t.Fatalf("tc.io.ReadFile(\"-\") failed: %v", err)
			}
			if diff := cmp.Diff(out, tc.want); diff != "" {
				t.Fatalf("verify %s output unexpected (-got, +want) %s", strings.Join(tc.input, " "), diff)
			}
		})
	}
}

func TestSevPolicy(t *testing.T) {
	mu.Do(initQuote(t))
	endorsementPath := "endorsement.binarypb"
	goodBasePath := "base.binarypb"
	goodBase, err := proto.Marshal(&cpb.Policy{
		Policy:       (1 << 17) | (1 << 18) | (1 << 16),
		PlatformInfo: &wrapperspb.UInt64Value{Value: 1},
	})
	if err != nil {
		t.Fatalf("failed to marshal base: %v", err)
	}
	wantProto := func(want *cpb.Policy, unmarshal func(got []byte, m proto.Message) error) func(got []byte) error {
		return func(got []byte) error {
			gotProto := &cpb.Policy{}
			if err := unmarshal(got, gotProto); err != nil {
				return fmt.Errorf("failed to unmarshal policy: %v", err)
			}
			if diff := cmp.Diff(gotProto, want, protocmp.Transform()); diff != "" {
				return fmt.Errorf("(-got, +want) %s", diff)
			}
			return nil
		}
	}
	tcs := []struct {
		name    string
		input   []string
		getter  trust.HTTPSGetter
		io      *testIO
		want    func(got []byte) error
		wantErr string
		outpath string
	}{
		{
			name:  "success",
			input: []string{endorsementPath, "--launch_vmsas", "1"},
			io: &testIO{
				files: map[string]*ioResult{
					endorsementPath: &ioResult{readBytes: fakeEndorsement},
				},
			},
			want: wantProto(&cpb.Policy{
				Policy:         (1 << 17) | (1 << 18) | (1 << 16),
				MinimumVersion: "0.0",
				Measurement:    cleanSnpMeasurement,
			},
				prototext.Unmarshal),
		},
		{
			name:  "success binProto",
			input: []string{endorsementPath, "--launch_vmsas", "1", "--out", "foo"},
			io: &testIO{
				files: map[string]*ioResult{
					endorsementPath: &ioResult{readBytes: fakeEndorsement},
				},
			},
			want: wantProto(&cpb.Policy{
				Policy:         (1 << 17) | (1 << 18) | (1 << 16),
				MinimumVersion: "0.0",
				Measurement:    cleanSnpMeasurement,
			},
				proto.Unmarshal),
			outpath: "foo",
		},
		{
			name:  "success with base",
			input: []string{endorsementPath, "--launch_vmsas", "1", "--out", "foo", "--base", goodBasePath},
			io: &testIO{
				files: map[string]*ioResult{
					endorsementPath: &ioResult{readBytes: fakeEndorsement},
					goodBasePath:    &ioResult{readBytes: goodBase},
				},
			},
			want: wantProto(&cpb.Policy{
				Policy:       (1 << 17) | (1 << 18) | (1 << 16),
				Measurement:  cleanSnpMeasurement,
				PlatformInfo: &wrapperspb.UInt64Value{Value: 1},
			},
				proto.Unmarshal),
			outpath: "foo",
		},
		{
			name:    "gen fail",
			wantErr: "failed to generate sev policy",
			input:   []string{endorsementPath},
			io: &testIO{
				files: map[string]*ioResult{
					endorsementPath: &ioResult{readBytes: fakeEndorsement},
				},
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			c := MakeRoot(context.WithValue(context.Background(), backendKey, &Backend{
				Provider: qp,
				Getter:   tc.getter,
				Now:      now,
				IO:       tc.io,
			}))
			c.SetArgs(append([]string{"sev", "policy"}, tc.input...))
			if err := c.Execute(); !match.Error(err, tc.wantErr) {
				t.Fatalf("sev policy %s errored unexpectedly. Got %v, want %q", strings.Join(tc.input, " "),
					err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			outpath := "-"
			if tc.outpath != "" {
				outpath = tc.outpath
			}
			got, err := tc.io.ReadFile(outpath)
			if err != nil {
				t.Fatalf("tc.io.ReadFile(%q) failed: %v", outpath, err)
			}
			if err := tc.want(got); err != nil {
				t.Fatalf("sev policy %s output unexpected: %v", strings.Join(tc.input, " "), err)
			}
		})
	}
}

func TestSevValidate(t *testing.T) {
	mu.Do(initQuote(t))
	endorsementPath := "endorsement.binarypb"
	rootPath := "root.pem"
	quotePath := "attestation.bin"
	tcs := []struct {
		name    string
		input   []string
		getter  trust.HTTPSGetter
		io      *testIO
		wantErr string
	}{
		{
			name:  "success local quote, provided endorsement, local root",
			input: []string{quotePath, "--endorsement", endorsementPath, "--root_cert", rootPath},
			io: &testIO{
				files: map[string]*ioResult{
					endorsementPath: &ioResult{readBytes: fakeEndorsement},
					rootPath:        &ioResult{readBytes: devkeys.RootCert},
					quotePath:       &ioResult{readBytes: goodSnpQuote},
				},
			},
		},
		{
			name:  "fail endorsement fail not found",
			input: []string{quotePath, "--endorsement", endorsementPath, "--root_cert", rootPath},
			io: &testIO{
				files: map[string]*ioResult{
					rootPath:  &ioResult{readBytes: devkeys.RootCert},
					quotePath: &ioResult{readBytes: goodSnpQuote},
				},
			},
			wantErr: "failed to read file",
		},
		{
			name:  "fail root not found",
			input: []string{quotePath, "--root_cert", rootPath},
			io: &testIO{
				files: map[string]*ioResult{
					quotePath: &ioResult{readBytes: goodSnpQuote},
				},
			},
			wantErr: "failed to get root certificate",
		},
		{
			name:    "quote file not found",
			input:   []string{quotePath},
			io:      &testIO{},
			wantErr: "failed to read attestation file",
		},
		{
			name:    "need 1 argument",
			input:   []string{},
			io:      &testIO{},
			wantErr: "sev validate expects exactly one positional argument, got 0",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			c := MakeRoot(context.WithValue(context.Background(), backendKey, &Backend{
				Provider: qp,
				Getter:   getter,
				Now:      now,
				IO:       tc.io,
			}))
			c.SetArgs(append([]string{"sev", "validate"}, tc.input...))
			if err := c.Execute(); !match.Error(err, tc.wantErr) {
				t.Fatalf("sev validate %s errored unexpectedly. Got %v, want %q", strings.Join(tc.input, " "), err, tc.wantErr)
			}
		})
	}
}

func TestTdxPolicy(t *testing.T) {
	mu.Do(initQuote(t))
	endorsementPath := "endorsement.binarypb"
	goodBasePath := "base.binarypb"
	goodBase, err := proto.Marshal(&tcpb.Policy{})
	if err != nil {
		t.Fatalf("failed to marshal base: %v", err)
	}
	wantProto := func(want *tcpb.Policy, unmarshal func(got []byte, m proto.Message) error) func(got []byte) error {
		return func(got []byte) error {
			gotProto := &tcpb.Policy{}
			if err := unmarshal(got, gotProto); err != nil {
				return fmt.Errorf("failed to unmarshal policy: %v", err)
			}
			if diff := cmp.Diff(gotProto, want, protocmp.Transform()); diff != "" {
				return fmt.Errorf("(-got, +want) %s", diff)
			}
			return nil
		}
	}
	tcs := []struct {
		name    string
		input   []string
		getter  trust.HTTPSGetter
		io      *testIO
		want    func(got []byte) error
		wantErr string
		outpath string
	}{
		{
			name:  "success",
			input: []string{endorsementPath},
			io: &testIO{
				files: map[string]*ioResult{
					endorsementPath: &ioResult{readBytes: fakeEndorsement},
				},
			},
			want: wantProto(&tcpb.Policy{
				TdQuoteBodyPolicy: &tcpb.TDQuoteBodyPolicy{AnyMrTd: [][]byte{cleanTdxMeasurement}},
			},
				prototext.Unmarshal),
		},
		{
			name:  "success binProto",
			input: []string{endorsementPath, "--out", "foo"},
			io: &testIO{
				files: map[string]*ioResult{
					endorsementPath: &ioResult{readBytes: fakeEndorsement},
				},
			},
			want: wantProto(&tcpb.Policy{
				TdQuoteBodyPolicy: &tcpb.TDQuoteBodyPolicy{AnyMrTd: [][]byte{cleanTdxMeasurement}},
			},
				proto.Unmarshal),
			outpath: "foo",
		},
		{
			name:  "success with base",
			input: []string{endorsementPath, "--out", "foo", "--base", goodBasePath},
			io: &testIO{
				files: map[string]*ioResult{
					endorsementPath: &ioResult{readBytes: fakeEndorsement},
					goodBasePath:    &ioResult{readBytes: goodBase},
				},
			},
			want: wantProto(&tcpb.Policy{
				TdQuoteBodyPolicy: &tcpb.TDQuoteBodyPolicy{AnyMrTd: [][]byte{cleanTdxMeasurement}},
			},
				proto.Unmarshal),
			outpath: "foo",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			c := MakeRoot(context.WithValue(context.Background(), backendKey, &Backend{
				Provider: qp,
				Getter:   tc.getter,
				Now:      now,
				IO:       tc.io,
			}))
			c.SetArgs(append([]string{"tdx", "policy"}, tc.input...))
			if err := c.Execute(); !match.Error(err, tc.wantErr) {
				t.Fatalf("tdx policy %s errored unexpectedly. Got %v, want %q", strings.Join(tc.input, " "),
					err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			outpath := "-"
			if tc.outpath != "" {
				outpath = tc.outpath
			}
			got, err := tc.io.ReadFile(outpath)
			if err != nil {
				t.Fatalf("tc.io.ReadFile(%q) failed: %v", outpath, err)
			}
			if err := tc.want(got); err != nil {
				t.Fatalf("tdx policy %s output unexpected: %v", strings.Join(tc.input, " "), err)
			}
		})
	}
}
