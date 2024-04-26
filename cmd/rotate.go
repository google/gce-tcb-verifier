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
	"context"
	"math/big"
	"time"

	"github.com/google/gce-tcb-verifier/rotate"
	sops "github.com/google/gce-tcb-verifier/sign/ops"
	"github.com/spf13/cobra"
)

// RotateCommand provides the core CommandComponent for executing a key rotation. This must be
// defined in cmd instead of on top of rotate.SignerKeyContext since rotate cannot depend on cmd to
// do so.
type RotateCommand struct{}

// addRotateFlags adds the basic flags for any key rotation command implementation.

// AddFlags adds core flags for populating a rotate.SigningKeyContext.
func (r *RotateCommand) AddFlags(cmd *cobra.Command) {
	skc := &rotate.SigningKeyContext{}
	cmd.SetContext(rotate.NewSigningKeyContext(cmd.Context(), skc))
	addSigningKeyCommonNameFlag(cmd, &skc.SigningKeyCommonName)
	cmd.PersistentFlags().AddGoFlag(bigintVar(&skc.SigningKeySerial, "rotated_key_serial_override",
		"0", "A forced serial number of the rotated key (0 is default behavior: current key's serial + 1)."))
	addTimeFlag(cmd, &skc.Now)
}

// PersistentPreRunE returns an error if the results of the parsed flags constitute an error.
func (r *RotateCommand) PersistentPreRunE(cmd *cobra.Command, _ []string) error {
	skc, err := rotate.FromSigningKeyContext(cmd.Context())
	if err != nil {
		return err
	}
	if skc.Now.IsZero() {
		skc.Now = time.Now()
	}
	return nil
}

// InitContext extends the given context with whatever else the component needs before execution.
func (r *RotateCommand) InitContext(ctx context.Context) (context.Context, error) {
	skc, err := rotate.FromSigningKeyContext(ctx)
	if err != nil {
		return nil, err
	}
	// 0 for the override means use the default behavior of current + 1.
	if skc.SigningKeySerial.Cmp(big.NewInt(0)) == 0 {
		skc.SigningKeySerial, err = sops.NextSigningKeySerial(ctx)
	}
	return ctx, err
}

func makeRotateCmd(ctx context.Context, app *AppComponents) *cobra.Command {
	cmp := Compose(app.Global, &RotateCommand{}, app.Rotate)
	cmd := &cobra.Command{
		Use: "rotate [flags]",
		Long: `Rotates the current signing key.

The signing key's common name (certificate) and key name (resource) are required.`,
		PersistentPreRunE: cmp.PersistentPreRunE,
		RunE: ComposeRun(cmp, func(ctx context.Context) error {
			_, err := rotate.Key(ctx)
			return err
		}),
	}
	cmd.SetContext(ctx)
	cmp.AddFlags(cmd)
	return cmd
}
