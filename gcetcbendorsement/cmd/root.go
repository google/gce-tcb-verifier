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

// Package cmd provides the gcetcbendorsement CLI command abstractions.
package cmd

import (
	"errors"
	"context"
	"time"

	"github.com/google/gce-tcb-verifier/extract"
	"github.com/google/gce-tcb-verifier/verify"
	"github.com/google/go-sev-guest/client/client"
	"github.com/google/go-sev-guest/verify/trust/trust"
	"github.com/google/logger"
	"github.com/spf13/cobra"
)

var (
	// RootCmd is the canonical root cobra command for the gcetcbendorsement CLI.
	RootCmd      *cobra.Command
	errNoBackend = errors.New("no backend in context")
)

// Backend provides implementations for quote creation, internet access, and the current time.
type Backend struct {
	Provider extract.QuoteProvider
	Getter   verify.HTTPSGetter
	Now      time.Time
	IO       IO
}

type backendKeyType struct{}

var backendKey backendKeyType

func backendFrom(ctx context.Context) (*Backend, error) {
	b, ok := ctx.Value(backendKey).(*Backend)
	if !ok {
		return nil, errNoBackend
	}
	return b, nil
}

// MakeRoot returns a new root cobra command for the gcetcbendorsement CLI tool.
func MakeRoot(ctx0 context.Context) *cobra.Command {
	cobra.EnableTraverseRunHooks = true
	cmd := &cobra.Command{
		Use:  "gcetcbendorsement",
		Long: `Command line tool for interpreting GCE UEFI signatures.`,
	}
	cmd.AddCommand(makeExtract(ctx0))
	cmd.AddCommand(makeInspect(ctx0))
	cmd.AddCommand(makeVerify(ctx0))
	cmd.AddCommand(makeSevCommand(ctx0))
	return cmd

}

func init() {
	qp, err := client.GetQuoteProvider()
	if err != nil {
		logger.Fatal(err)
	}
	RootCmd = MakeRoot(context.WithValue(context.Background(), backendKey, &Backend{
		Provider: qp,
		Getter:   trust.DefaultHTTPSGetter(),
		Now:      time.Now(),
		IO:       OSIO{},
	}))
}
