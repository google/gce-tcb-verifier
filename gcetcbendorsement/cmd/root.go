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
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/gce-tcb-verifier/extract"
	exel "github.com/google/gce-tcb-verifier/extract/eventlog"
	"github.com/google/gce-tcb-verifier/verify"
	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/verify/trust"
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
	Provider              extract.QuoteProvider
	Getter                verify.HTTPSGetter
	MakeEfiVariableReader func(mountpath string) exel.VariableReader
	Now                   time.Time
	IO                    IO
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
	cmd.AddCommand(makeTdxCommand(ctx0))
	cmd.SetContext(ctx0)
	return cmd
}

type bearerGetter struct {
	token string
}

func (b *bearerGetter) Get(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %q: %v", url, err)
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get %q: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get %q: %v", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func init() {
	var bearer string
	var timeout time.Duration
	p, err := client.GetQuoteProvider()
	if err != nil {
		logger.Fatalf("Failed to get quote provider: %v", err)
	}
	RootCmd = MakeRoot(context.WithValue(context.Background(), backendKey, &Backend{
		Provider: p,
		MakeEfiVariableReader: func(path string) exel.VariableReader {
			return exel.MakeEfiVarFSReader(path)
		},
		Now: time.Now(),
		IO:  OSIO{},
	}))
	RootCmd.PersistentFlags().StringVar(&bearer, "auth_token", "", "Bearer token to use for HTTP requests.")
	RootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 2*time.Minute, "Timeout for HTTPS GET requests")
	RootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		var baseGetter verify.HTTPSGetter
		if bearer == "" {
			baseGetter = &trust.SimpleHTTPSGetter{}
		} else {
			baseGetter = &bearerGetter{token: bearer}
		}
		b, _ := backendFrom(cmd.Context())
		b.Getter = &trust.RetryHTTPSGetter{
			Timeout:       timeout,
			MaxRetryDelay: 30 * time.Second,
			Getter:        baseGetter,
		}
	}
	RootCmd.TraverseChildren = true
}
