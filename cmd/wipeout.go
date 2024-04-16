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

	"github.com/google/gce-tcb-verifier/rotate"
	"github.com/spf13/cobra"
)

func wipeoutBase() CommandComponent {
	return &PartialComponent{
		FAddFlags: func(cmd *cobra.Command) {
			w := &rotate.WipeoutContext{}
			cmd.SetContext(rotate.NewWipeoutContext(cmd.Context(), w))
			cmd.PersistentFlags().BoolVar(&w.Force, "force_prod_wipeout", false,
				"Forces the wipeout operation to run even in a production environment.")
		},
	}
}

func makeWipeoutCmd(ctx context.Context, app *AppComponents) *cobra.Command {
	cmp := Compose(app.Global, wipeoutBase(), app.Wipeout)
	cmd := &cobra.Command{
		Use:               "wipeout [flags]",
		Long:              `Destroys all managed keys and certificates.`,
		PersistentPreRunE: cmp.PersistentPreRunE,
		RunE:              ComposeRun(cmp, rotate.Wipeout),
	}
	cmd.SetContext(ctx)
	cmp.AddFlags(cmd)
	return cmd
}
