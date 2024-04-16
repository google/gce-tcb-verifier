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
	"golang.org/x/net/context"

	"github.com/google/gce-tcb-verifier/cmd/output"
	"github.com/google/gce-tcb-verifier/keys"
	"github.com/spf13/cobra"
)

// makeRootCmd creates an entrypoint for endorse.
func makeRootCmd(ctx0 context.Context, app *AppComponents) *cobra.Command {
	flags := &output.Options{}
	ctx := output.NewContext(ctx0, flags)
	cmd := &cobra.Command{
		Use: "endorse",
		Long: `Command line tool for GCE UEFI signing

This tool allows signing with CloudKMS keys, provided RSA keys, or generated keys.
`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := flags.Validate(cmd); err != nil {
				return err
			}
			// TODO: Make unconditional when Keys is provided by all Apps.
			if app.Global != nil {
				if err := app.Global.PersistentPreRunE(cmd, args); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.SetContext(keys.NewContext(ctx, &keys.Context{Random: app.SignatureRandom}))
	// TODO: Make unconditional when Global is provided by all Apps.
	if app.Global != nil {
		app.Global.AddFlags(cmd)
	}
	flags.AddFlags(cmd)
	return cmd
}

type runFn func(*cobra.Command, []string) error
