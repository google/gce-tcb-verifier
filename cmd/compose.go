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
	"io"

	"github.com/spf13/cobra"
)

// CommandComponent represents any setup that must happen before running a command.
type CommandComponent interface {
	// InitContext extends the given context with whatever else the component needs before execution.
	// This is separate from PersistentPreRunE to allow all flag validation code to run before
	// performing these potentially expensive initialization actions.
	InitContext(ctx context.Context) (context.Context, error)
	// AddFlags adds any implementation-specific flags for this command component.
	AddFlags(cmd *cobra.Command)
	// PersistentPreRunE returns an error if the results of the parsed flags constitute an error.
	PersistentPreRunE(cmd *cobra.Command, args []string) error
}

// AppComponents contains implementations of application interfaces needed to instantiate the entire
// GCE TCB CLI tool.
type AppComponents struct {
	// Endorse abstracts any extra endorsement setup to do on top of the base before performing an
	// endorsement.
	Endorse CommandComponent
	// Global provides flags, validation, and context for every command. Its context must be
	// initialized explicitly.
	Global CommandComponent
	// SignatureRandom is the source of randomness used for certificate signature salting.
	SignatureRandom io.Reader
	// Bootstrap abstracts any extra setup to do on top of the base before performing key
	// bootstrapping.
	Bootstrap CommandComponent
	// Rotate abstracts any extra setup to do on top of the base before performing key rotation.
	Rotate CommandComponent
	// Wipeout abstracts any extra setup to do on top of the base before destroying all keys and
	// key certificates.
	Wipeout CommandComponent
}

// MakeApp returns an initialized cobra root command for a CLI tool that includes all expected
// subcommands.
func MakeApp(ctx context.Context, app *AppComponents) *cobra.Command {
	root := makeRootCmd(ctx, app)
	root.AddCommand(makeEndorseCmd(root.Context(), app))
	root.AddCommand(makeBootstrapCmd(root.Context(), app))
	root.AddCommand(makeRotateCmd(root.Context(), app))
	root.AddCommand(makeWipeoutCmd(root.Context(), app))
	return root
}

// ComposeInitContext returns the sequenced context initialization of all provided components'
// InitContext functions, or the first error encountered.
func ComposeInitContext(ctx0 context.Context, cmps ...CommandComponent) (ctx context.Context, err error) {
	ctx = ctx0
	for _, c := range cmps {
		if c == nil {
			continue
		}
		ctx, err = c.InitContext(ctx)
		if err != nil {
			return nil, err
		}
	}
	return ctx, nil
}

// ComposedComponent dispatches to the encapsulated components in sequence for each of their
// functions.
type ComposedComponent struct {
	Components []CommandComponent
}

// InitContext extends the given context with whatever else the held components need before
// execution.
func (c *ComposedComponent) InitContext(ctx context.Context) (context.Context, error) {
	return ComposeInitContext(ctx, c.Components...)
}

// AddFlags adds any implementation-specific flags for the held command components.
func (c *ComposedComponent) AddFlags(cmd *cobra.Command) {
	for _, cmp := range c.Components {
		if cmp == nil {
			continue
		}
		cmp.AddFlags(cmd)
	}
}

// PersistentPreRunE returns an error if the results of the parsed flags constitute an error.
func (c *ComposedComponent) PersistentPreRunE(cmd *cobra.Command, args []string) error {
	for _, cmp := range c.Components {
		if cmp == nil {
			continue
		}
		if err := cmp.PersistentPreRunE(cmd, args); err != nil {
			return err
		}
	}
	return nil
}

// Compose returns a component that composes all the given components in the order given.
func Compose(cmps ...CommandComponent) *ComposedComponent { return &ComposedComponent{cmps} }

// PartialComponent implements a CommandComponent with the provided functions. Missing fields have
// reasonable default behavior.
type PartialComponent struct {
	// InitContext extends the given context with whatever else the component needs before execution.
	FInitContext func(ctx context.Context) (context.Context, error)
	// AddFlags adds any implementation-specific flags for this command component.
	FAddFlags func(cmd *cobra.Command)
	// PersistentPreRunE returns an error if the results of the parsed flags constitute an error.
	FPersistentPreRunE func(cmd *cobra.Command, args []string) error
}

// InitContext extends the given context with whatever else the component needs before execution.
func (p *PartialComponent) InitContext(ctx context.Context) (context.Context, error) {
	if p.FInitContext == nil {
		return ctx, nil
	}
	return p.FInitContext(ctx)
}

// AddFlags adds any implementation-specific flags for this command component.
func (p *PartialComponent) AddFlags(cmd *cobra.Command) {
	if p.FAddFlags != nil {
		p.FAddFlags(cmd)
	}
}

// PersistentPreRunE returns an error if the results of the parsed flags constitute an error.
func (p *PartialComponent) PersistentPreRunE(cmd *cobra.Command, args []string) error {
	if p.FPersistentPreRunE == nil {
		return nil
	}
	return p.FPersistentPreRunE(cmd, args)
}

// ComposeRun will return run called with a command's context that has been extended by cmp's
// InitContext if cmp is non-nil.
func ComposeRun(cmp CommandComponent, run func(context.Context) error) RunFn {
	return func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		if cmp != nil {
			var err error
			ctx, err = cmp.InitContext(cmd.Context())
			if err != nil {
				return err
			}
		}
		return run(ctx)
	}
}
