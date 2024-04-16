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

package memkm

import (
	"fmt"
	"golang.org/x/net/context"
	"testing"
	"time"

	"github.com/google/gce-tcb-verifier/cmd"
	"github.com/google/gce-tcb-verifier/keys"
	"github.com/google/gce-tcb-verifier/sign/memca"
	"github.com/google/gce-tcb-verifier/sign/nonprod"
	"github.com/google/gce-tcb-verifier/testing/testkm"
	"github.com/google/gce-tcb-verifier/testing/testsign"
	"github.com/spf13/cobra"
)

func TestBumpName(t *testing.T) {
	tcs := []struct {
		input string
		want  string
	}{
		{
			input: "primarySigningKey",
			want:  "primarySigningKey_1",
		},
		{
			input: "primarySigningKey_1",
			want:  "primarySigningKey_2",
		},
		{
			input: "a_b_c",
			want:  "a_b_c_1",
		},
		{
			input: "a_b_c_12",
			want:  "a_b_c_13",
		},
	}
	for _, tc := range tcs {
		t.Run(fmt.Sprintf("BumpName(%q)", tc.input), func(t *testing.T) {
			got := BumpName(tc.input)
			if got != tc.want {
				t.Errorf("BumpName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNonprodBootstrap(t *testing.T) {
	ctx0 := context.Background()
	s := &nonprod.Signer{Rand: testsign.RootRand()}
	ctx := keys.NewContext(ctx0, &keys.Context{
		Signer:  s,
		CA:      memca.Create(),
		Manager: &T{Signer: s},
		Random:  testsign.RootRand(),
	})
	testkm.Bootstrap(ctx, t)
}

func TestNonprodRotate(t *testing.T) {
	ctx0 := context.Background()
	now := time.Now()
	ca := memca.Create()
	s, err := testsign.MakeSigner(ctx0, &testsign.Options{
		Now:               now,
		CA:                ca,
		Root:              testsign.KeyInfo{CommonName: "rootCn", KeyVersionName: "root"},
		PrimarySigningKey: testsign.KeyInfo{CommonName: "signerCn", KeyVersionName: "primarySigningKey"},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := &T{Signer: s}
	c := &cobra.Command{}
	// This SetContext is done by the root command.
	c.SetContext(keys.NewContext(ctx0, &keys.Context{Random: testsign.SignerRand()}))
	m.AddFlags(c)
	ca.AddFlags(c)
	ctx, err := cmd.ComposeInitContext(c.Context(), m, ca)
	if err != nil {
		t.Fatal(err)
	}
	testkm.Rotate(ctx, t, "primarySigningKey_1")
}

func TestNonprodWipeout(t *testing.T) {
	m := &T{Signer: &nonprod.Signer{Rand: testsign.RootRand()}}
	ca := memca.Create()
	c := &cobra.Command{}
	ctx0 := context.Background()
	c.SetContext(keys.NewContext(ctx0, &keys.Context{Random: testsign.SignerRand()}))
	m.AddFlags(c)
	ca.AddFlags(c)

	ctx, err := cmd.ComposeInitContext(c.Context(), m, ca)
	if err != nil {
		t.Fatal(err)
	}
	testkm.Wipeout(ctx, t)
}
