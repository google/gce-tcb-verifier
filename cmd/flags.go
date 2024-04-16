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
	"errors"
	"flag"
	"fmt"
	"math/big"
	"time"

	"github.com/google/go-sev-guest/kds"
	sgpb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/spf13/cobra"
)

var (
	// ErrTimeAlreadySet is returned from a timeFlag parsing if the value has already been set.
	ErrTimeAlreadySet = errors.New("time flag has already been set")
)

// Lets this command specify an input UEFI file.
func addUefiFlag(cmd *cobra.Command, f *string) {
	cmd.PersistentFlags().StringVar(f, "uefi", "", "Path to UEFI binary")
}

// Lets this command specify an output directory.
func addOutDirFlag(cmd *cobra.Command, f *string) {
	cmd.PersistentFlags().StringVar(f, "out_dir", "",
		"Directory in which the manifest and certificates are read and written.")
}

func addDryRunFlag(cmd *cobra.Command, f *bool) {
	cmd.PersistentFlags().BoolVar(f, "dry_run", false,
		"If true, writes no files and commits nothing.")
}

func addSigningKeyCommonNameFlag(cmd *cobra.Command, f *string) {
	cmd.PersistentFlags().StringVar(f, "signing_key_cn", "GCE-uefi-signer",
		"The signing key's certificate subject common name.")
}

type timeFlag struct {
	t *time.Time
}

func (t *timeFlag) String() string {
	if t.t == nil {
		return "nil"
	}
	return (*t.t).Format(time.RFC3339)
}

func (t *timeFlag) Set(value string) error {
	if t.t == nil {
		return errors.New("time flag value destination cannot be nil")
	}
	if !(*t.t).IsZero() {
		return ErrTimeAlreadySet
	}
	if value != "" {
		v, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return fmt.Errorf("--timestamp must be in RFC3339 format, got %q", value)
		}
		*t.t = v
		return nil
	}
	return nil
}

func addTimeFlag(cmd *cobra.Command, f *time.Time) {
	cmd.PersistentFlags().AddGoFlag(&flag.Flag{
		Name:     "timestamp",
		Value:    &timeFlag{t: f},
		Usage:    "Specify a specific time in RFC3339 format to be used as the basis of generated certificates.",
		DefValue: "",
	})
}

type bigintFlag struct {
	v **big.Int
}

func (b *bigintFlag) String() string {
	if b.v == nil {
		return "<unset>"
	}
	return (*b.v).String()
}

func (b *bigintFlag) Set(value string) error {
	if value != "" {
		v, ok := new(big.Int).SetString(value, 10)
		if !ok {
			return fmt.Errorf("%s is not a decimal integer", value)
		}
		*b.v = v
		return nil
	}
	return nil
}

func bigintVar(v **big.Int, name, defaultValue, usage string) *flag.Flag {
	f := &bigintFlag{v: v}
	defaultV, ok := new(big.Int).SetString(defaultValue, 10)
	if !ok {
		panic(fmt.Errorf("internal: bad default bigint value %q", defaultValue))
	}
	*v = defaultV
	return &flag.Flag{
		Name:     name,
		Value:    f,
		Usage:    usage,
		DefValue: defaultValue,
	}
}

type amdProductFlag struct {
	v *sgpb.SevProduct_SevProductName
}

func (p *amdProductFlag) String() string {
	if p.v == nil {
		return "<unset>"
	}
	return kds.ProductLine(&sgpb.SevProduct{Name: *p.v})
}

func (p *amdProductFlag) Set(value string) error {
	if value != "" {
		product, err := kds.ParseProductLine(value)
		if err != nil {
			return err
		}
		*p.v = product.Name
		return nil
	}
	return nil
}

func amdProductVar(v *sgpb.SevProduct_SevProductName, name string, defaultValue sgpb.SevProduct_SevProductName, usage string) *flag.Flag {
	f := &amdProductFlag{v: v}
	*v = defaultValue
	return &flag.Flag{
		Name:     name,
		Value:    f,
		Usage:    usage,
		DefValue: kds.ProductLine(&sgpb.SevProduct{Name: defaultValue}),
	}
}
