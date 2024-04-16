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

// Package nonprod implements local signing and file operations for signing and submitting
// endorsements to disk.
package nonprod

import (
	"crypto/rand"
	"golang.org/x/net/context"

	"github.com/google/gce-tcb-verifier/cmd"
	"github.com/google/gce-tcb-verifier/endorse"
	"github.com/google/gce-tcb-verifier/sign/nonprod"
	"github.com/google/gce-tcb-verifier/testing/nonprod/localca"
	"github.com/google/gce-tcb-verifier/testing/nonprod/localkm"
	"github.com/google/gce-tcb-verifier/testing/nonprod/localnonvcs"
	"github.com/google/gce-tcb-verifier/testing/nonprod/memkm"
	"github.com/spf13/cobra"
)

var (
	// RootCmd is the cobra representation of the nonprod root command.
	RootCmd *cobra.Command
)

func localApp() *cmd.AppComponents {
	return &cmd.AppComponents{
		Endorse: cmd.Compose(cmd.EndorseSetterE(func(ec *endorse.Context) error {
			ec.ClSpec = 123
			return nil
		}),
			&localnonvcs.T{}),
		Bootstrap: &cmd.PartialComponent{},
		Global: cmd.Compose(&localkm.T{T: memkm.T{Signer: &nonprod.Signer{Rand: rand.Reader}}},
			&localca.T{}),
		SignatureRandom: rand.Reader,
	}
}

func init() {
	RootCmd = cmd.MakeApp(context.Background(), localApp())
}
