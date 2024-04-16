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

package types

import (
	"crypto"
	"golang.org/x/net/context"
)

// Digest is the input type for signatures, since we only sign digests.
type Digest struct {
	SHA256 []byte
}

// Signer is an interface for signing data.
type Signer interface {
	// Sign signs the given data with the named key and returns the standard signature format for the
	// key's type.
	Sign(ctx context.Context, keyName string, digest Digest, opts crypto.SignerOpts) ([]byte, error)
	// PublicKey returns the PEM encoded public key for the named key.
	PublicKey(ctx context.Context, keyName string) ([]byte, error)
}
