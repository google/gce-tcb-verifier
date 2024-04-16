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
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/net/context"
	"io"
	"math/big"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/google/gce-tcb-verifier/endorse"
	"github.com/google/gce-tcb-verifier/keys"
	oabi "github.com/google/gce-tcb-verifier/ovmf/abi"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/gce-tcb-verifier/testing/ovmfsev"
	"github.com/spf13/cobra"
)

func TestRootFlags(t *testing.T) {
	tcs := []struct {
		name    string
		args    []string
		app     *AppComponents
		wantErr string
	}{
		{
			name: "happy path",
			args: []string{},
		},
		{
			name:    "output conflict",
			args:    []string{"--verbose", "--quiet"},
			wantErr: "cannot specify both --quiet and --verbose",
		},
		{
			name: "key validation",
			args: []string{},
			app: &AppComponents{Global: &PartialComponent{
				FPersistentPreRunE: func(cmd *cobra.Command, args []string) error {
					return errors.New("forced error")
				},
			}},
			wantErr: "forced error",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if tc.app == nil {
				tc.app = &AppComponents{}
			}
			cmd := makeRootCmd(context.Background(), tc.app)
			// Avoid the usage error by defining a Run function.
			cmd.RunE = func(c *cobra.Command, args []string) error { return nil }
			cmd.SetArgs(tc.args)
			if err := cmd.Execute(); !match.Error(err, tc.wantErr) {
				t.Fatal(err)
			}
		})
	}
}

func TestBigIntFlag(t *testing.T) {
	var v *big.Int
	f := bigintFlag{v: &v}
	tcs := []struct {
		name      string
		args      []string
		defaultV  string
		want      *big.Int
		wantErr   string
		wantPanic string
	}{
		{
			name: "default works",
			want: big.NewInt(2),
		},
		{
			name: "small works",
			args: []string{"--bignum=12"},
			want: big.NewInt(12),
		},
		{
			name: "big works",
			args: []string{"--bignum=98765432123456789"},
			want: func() *big.Int {
				z, ok := new(big.Int).SetString("98765432123456789", 10)
				if !ok {
					t.Fatal("internal test error")
				}
				return z
			}(),
		},
		{
			name:      "non-number default errors",
			defaultV:  "abc",
			wantPanic: "internal: bad default bigint value \"abc\"",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			// AddFlag can fail but can't return error, so check for panic.
			defer func() {
				r := recover()
				rerr, ok := r.(error)
				if !ok {
					rerr = nil
				}
				if !match.Error(rerr, tc.wantPanic) {
					t.Fatalf("panic behavior %v, want %q", r, tc.wantPanic)
				}
			}()
			c := &cobra.Command{
				RunE: func(c *cobra.Command, args []string) error {
					if tc.want == nil {
						return nil
					}
					if v == nil {
						return fmt.Errorf("bigintFlag = nil, want %v (want %q)", tc.want, tc.wantErr)
					}
					if v.Cmp(tc.want) != 0 {
						return fmt.Errorf("bigintFlag = %v, want %v (wantErr %q)", *f.v, tc.want, tc.wantErr)
					}
					return nil
				},
			}
			c.SetArgs(tc.args)
			v = nil
			defaultV := "2"
			if tc.defaultV != "" {
				defaultV = tc.defaultV
			}
			c.PersistentFlags().AddGoFlag(bigintVar(&v, "bignum", defaultV, "test"))
			if err := c.Execute(); !match.Error(err, tc.wantErr) {
				t.Fatalf("bigint test returned %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestTimeFlag(t *testing.T) {
	var v time.Time
	f := timeFlag{t: &v}
	tcs := []struct {
		name     string
		args     []string
		defaultV string
		want     time.Time
		wantErr  string
	}{
		{
			name: "default works",
			want: time.Time{},
		},
		{
			name: "time works",
			args: []string{"--timestamp=2023-10-09T09:12:00Z"},
			want: time.Date(2023, time.October, 9, 9, 12, 0, 0, time.UTC),
		},
		{
			name:    "non-time works",
			args:    []string{"--timestamp=Tomorrow"},
			wantErr: "--timestamp must be in RFC3339 format, got \"Tomorrow\"",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			c := &cobra.Command{
				RunE: func(c *cobra.Command, args []string) error {
					if !v.Equal(tc.want) {
						return fmt.Errorf("timeFlag = %v, want %v (wantErr %q)", *f.t, tc.want, tc.wantErr)
					}
					return nil
				},
			}
			c.SetArgs(tc.args)
			v = time.Time{}
			c.PersistentFlags().AddGoFlag(&flag.Flag{
				Name:  "timestamp",
				Usage: "test",
				Value: &timeFlag{t: &v},
			})
			if err := c.Execute(); !match.Error(err, tc.wantErr) {
				t.Fatalf("time test returned %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestNoSevSnp(t *testing.T) {
	cmp := &endorseCommand{}
	wantRelease := "a/123456789.1"
	c := &cobra.Command{
		PersistentPreRunE: cmp.PersistentPreRunE,
		RunE: ComposeRun(cmp, func(ctx context.Context) error {
			ec, err := endorse.FromContext(ctx)
			if err != nil {
				return err
			}
			if ec.SevSnp != nil {
				return fmt.Errorf("endorse.SevSnp = %v, want nil", ec.SevSnp)
			}
			if ec.ReleaseBranch != wantRelease {
				return fmt.Errorf("endorse.ReleaseBranch = %v, want %v", ec.ReleaseBranch, wantRelease)
			}
			return nil
		}),
	}
	c.SetContext(keys.NewContext(context.Background(), &keys.Context{}))
	cmp.AddFlags(c)
	p := path.Join(t.TempDir(), "uefi.fd")
	if err := os.WriteFile(p, []byte(`touched`), 0644); err != nil {
		t.Fatal(err)
	}
	c.SetArgs([]string{
		"--add_snp=false",
		"--release_branch", wantRelease,
		"--snp_svn", "5",
		"--uefi", p,
	})
	if err := c.Execute(); err != nil {
		t.Fatalf("endorse test returned %v, want nil", err)
	}
}

func TestSevSnpMeasurementOnly(t *testing.T) {
	cmp := &endorseCommand{}
	c := &cobra.Command{
		PersistentPreRunE: cmp.PersistentPreRunE,
		RunE: ComposeRun(cmp, func(ctx context.Context) error {
			return endorse.Ovmf(ctx)
		}),
	}
	var firmware [0x1000]byte
	copy(firmware[0x800:], []byte("LGTMLGTMLGTMLGTM"))
	copy(firmware[0xa00:], []byte("LGTMLGTMLGTMLGTM"))
	if err := ovmfsev.InitializeSevGUIDTable(firmware[:], oabi.FwGUIDTableEndOffset, ovmfsev.SevEsAddrVal, ovmfsev.DefaultSnpSections()); err != nil {
		t.Fatalf("ovmfsev.InitializeSevGUIDTable() errored unexpectedly: %v", err)
	}
	c.SetContext(keys.NewContext(context.Background(), &keys.Context{}))
	cmp.AddFlags(c)
	p := path.Join(t.TempDir(), "uefi.fd")
	if err := os.WriteFile(p, firmware[:], 0644); err != nil {
		t.Fatal(err)
	}
	c.SetArgs([]string{
		"--add_snp",
		"--release_branch", "a/123456789.1",
		"--snp_product", "Milan",
		"--snp_launch_vmsas", "4",
		"--uefi", p,
		"--measurement_only",
	})

	storeStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	if err := c.Execute(); err != nil {
		t.Fatalf("endorse test returned %v, want nil", err)
	}
	w.Close()
	got, err := io.ReadAll(r)
	os.Stdout = storeStdout
	if err != nil {
		t.Fatalf("io.ReadAll of stdout pipe errored: %v", err)
	}
	lines := strings.Split(string(got), "\n")
	if len(lines) != 2 {
		t.Fatalf("endorse test returned %d lines, want 2", len(lines))
	}
	want := hex.EncodeToString([]byte{0x1a, 0x8c, 0xd8, 0x03, 0x9c, 0xdc, 0xdc, 0xd1, 0xec, 0x98, 0x00, 0xca, 0x21, 0x5b, 0xa5, 0xcb,
		0xbe, 0xd4, 0x37, 0x69, 0x7d, 0xeb, 0xf0, 0xb2, 0xfc, 0x1a, 0x9b, 0x87, 0x3f, 0x1e, 0xb1, 0x5f,
		0x82, 0xdc, 0x7d, 0x5c, 0xf2, 0x46, 0xdb, 0xee, 0x4d, 0xf1, 0xbb, 0x9d, 0x3b, 0x6c, 0x7a, 0x16})
	if lines[0] != want {
		t.Errorf("endorse test returned %q, want %q", got, want)
	}
}
