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

package rotate

import (
	"errors"
	"fmt"
	"golang.org/x/net/context"

	"github.com/google/gce-tcb-verifier/cmd/output"
	"github.com/google/gce-tcb-verifier/keys"
)

var (
	// ErrNoWipeoutContext is returned when FromWipeoutContext can't find the requisite
	// context.
	ErrNoWipeoutContext = errors.New("no WipeoutContext in context")
)

// WipeoutContext represents the intention to delete all managed keys and certificates.
// This context is provided for any specialization of wipeout that deems itself "production" to
// query if the operation should be permitted.
type WipeoutContext struct {
	Force bool
}

type wipeoutKeyType struct{}

var wipeoutKey wipeoutKeyType

// NewWipeoutContext returns ctx extended with the given WipeoutContext.
func NewWipeoutContext(ctx context.Context, f *WipeoutContext) context.Context {
	return context.WithValue(ctx, wipeoutKey, f)
}

// FromWipeoutContext returns the WipeoutContext in the context if it exists.
func FromWipeoutContext(ctx context.Context) (*WipeoutContext, error) {
	f, ok := ctx.Value(wipeoutKey).(*WipeoutContext)
	if !ok {
		return nil, ErrNoWipeoutContext
	}
	return f, nil
}

// Wipeout destroys all assets for the CA and all keys in the signer.
func Wipeout(ctx context.Context) error {
	c, err := keys.FromContext(ctx)
	if err != nil {
		return err
	}
	if c.CA == nil {
		return keys.ErrNoCertificateAuthority
	}
	if err := c.CA.Wipeout(ctx); err != nil {
		return fmt.Errorf("could not wipeout certificate authority: %w", err)
	}
	output.Infof(ctx, "Certificate authority wipeout completed.")
	if err := c.Manager.Wipeout(ctx); err != nil {
		return fmt.Errorf("could not wipeout keys: %w", err)
	}
	output.Infof(ctx, "Key manager wipeout completed.")
	return nil
}
