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

// Package keys provides context and management types for key signing and certificates.
package keys

import (
	"crypto/x509"
	"errors"
	"golang.org/x/net/context"
	"io"

	styp "github.com/google/gce-tcb-verifier/sign/types"
)

var (
	// ErrNoContext is the error that operations requiring a keys.Context will return when the
	// given context does not have a keys.Context.
	ErrNoContext = errors.New("context does not have keys.Context")
	// ErrNoCertificateAuthority is returned when keys.Context's CA is nil but shouldn't be.
	ErrNoCertificateAuthority = errors.New("keys.Context does not have a certificate authority")
	// ErrNoSigner is returned when keys.Context's Signer is nil but shouldn't be.
	ErrNoSigner = errors.New("keys.Context does not have a signer")
	// ErrNoManager is returned when keys.Context's Manager is nil but shouldn't be.
	ErrNoManager = errors.New("keys.Context does not have a key manager")
)

// ManagerInterface provides an abstraction over key creation, rotation, which includes
// granting certificates. It furthermore has the "wipeout" option to eliminate all keys it has
// created.
type ManagerInterface interface {
	// CreateFirstSigningKey is called during CA bootstrapping to create the first signing key that
	// can be used for endorse.
	CreateFirstSigningKey(ctx context.Context) (string, error)
	// CreateNewSigningKeyVersion is callable after CreateNewSigningKey, and is meant for key
	// rotation. The signing key's name ought to be available from the context.
	CreateNewSigningKeyVersion(ctx context.Context) (string, error)
	// CreateNewRootKey establishes a new key for use as the root CA key.
	CreateNewRootKey(ctx context.Context) (string, error)
	// CertificateTemplate returns a certificate template that will be used for signing.
	CertificateTemplate(ctx context.Context, issuer *x509.Certificate, subjectPubKey any) (*x509.Certificate, error)

	// DestroyKeyVersion destroys a single key version.
	DestroyKeyVersion(ctx context.Context, keyVersionName string) error
	// Wipeout destroys all keys managed by this manager.
	Wipeout(ctx context.Context) error
}

// Context encapsulates abstractions for key signing and certificate authority behavior for use
// in key subcommands.
type Context struct {
	// CA is a CertificateAuthority implementation.
	CA styp.CertificateAuthority
	// Signer is used to sign certificates.
	Signer styp.Signer
	// Random is a source of randomness for certificate signatures.
	Random io.Reader
	// Manager implements the key management operations of ManagerInterface
	Manager ManagerInterface
}

type contextKeyType struct{}

var contextKey contextKeyType

// NewContext returns a context extended with a given keys.Context.
func NewContext(ctx context.Context, c *Context) context.Context {
	return context.WithValue(ctx, contextKey, c)
}

// FromContext returns the context's rotate.Context if it exists.
func FromContext(ctx context.Context) (*Context, error) {
	v := ctx.Value(contextKey)
	if v == nil {
		return nil, ErrNoContext
	}
	return v.(*Context), nil
}
