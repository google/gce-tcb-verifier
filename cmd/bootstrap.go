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
	"time"

	"github.com/google/gce-tcb-verifier/rotate"
	"github.com/spf13/cobra"
)

// BootstrapCommand is the core bootstrap command component.
type BootstrapCommand struct{}

// InitContext extends the given context with whatever else the component needs before execution.
func (b *BootstrapCommand) InitContext(ctx context.Context) (context.Context, error) {
	return ctx, nil
}

// AddFlags adds any implementation-specific flags for this command component.
func (b *BootstrapCommand) AddFlags(cmd *cobra.Command) {
	bc := &rotate.BootstrapContext{}
	cmd.PersistentFlags().StringVar(&bc.RootKeyCommonName, "root_key_cn", "GCE-cc-tcb-root",
		"The root key's certificate subject common name.")
	addSigningKeyCommonNameFlag(cmd, &bc.SigningKeyCommonName)
	cmd.SetContext(rotate.NewBootstrapContext(cmd.Context(), bc))
	cmd.PersistentFlags().AddGoFlag(bigintVar(
		&bc.RootKeySerial, "root_key_serial", "1", "The serial number of the root key."))
	cmd.PersistentFlags().AddGoFlag(bigintVar(
		&bc.SigningKeySerial, "initial_signing_key_serial", "2",
		"The serial number of the initial signing key in decimal."))
	addTimeFlag(cmd, &bc.Now)
}

// PersistentPreRunE returns an error if the results of the parsed flags constitute an error.
func (b *BootstrapCommand) PersistentPreRunE(cmd *cobra.Command, args []string) error {
	bc, err := rotate.FromBootstrapContext(cmd.Context())
	if err != nil {
		return err
	}
	// These flags are set in PersistentPreRunE since they would have been populated by flag parsing
	// and available at this point had they been able to directly attach to the context.
	if bc.Now.IsZero() {
		bc.Now = time.Now()
	}
	return nil
}

func makeBootstrapCmd(ctx context.Context, app *AppComponents) *cobra.Command {
	// A bootstrap command is the global component, followed by the core bootstrap command component,
	// followed by the app's specialized bootstrap component.
	cmp := Compose(app.Global, &BootstrapCommand{}, app.Bootstrap)
	cmd := &cobra.Command{
		Use: "bootstrap [flags]",
		Long: `Creates the first root key, signing key, and their certificates.

The signer key's common name (certificate) and key name (resource) are required.`,
		RunE:              ComposeRun(cmp, rotate.Bootstrap),
		PersistentPreRunE: cmp.PersistentPreRunE,
	}
	cmd.SetContext(ctx)
	cmp.AddFlags(cmd)
	return cmd
}
