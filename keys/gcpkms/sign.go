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

package gcpkms

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"hash/crc32"

	"cloud.google.com/go/kms/apiv1/kmspb"
	styp "github.com/google/gce-tcb-verifier/sign/types"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Signer implements sops.Signer for signing hashes with named keys.
type Signer struct {
	Manager *Manager
}

// PublicKey returns the public key for the named key version.
func (s *Signer) PublicKey(ctx context.Context, keyVersionName string) ([]byte, error) {
	pub, err := s.Manager.KeyClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: keyVersionName})
	if err != nil {
		return nil, err
	}
	return []byte(pub.GetPem()), nil
}

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// Sign uses the Signer's key manager to sign a digest with the given keyVersionName.
func (s *Signer) Sign(ctx context.Context, keyVersionName string, digest styp.Digest, opts crypto.SignerOpts) ([]byte, error) {
	wantOpts := rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	got, ok := opts.(*rsa.PSSOptions)
	if !ok || *got != wantOpts {
		return nil, fmt.Errorf("got signer options %v, want %v", got, wantOpts)
	}

	crc32cAsInt64 := func(data []byte) int64 {
		return int64(crc32.Checksum(data, crc32cTable))
	}
	request := &kmspb.AsymmetricSignRequest{
		Name:         keyVersionName,
		Digest:       &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest.SHA256}},
		DigestCrc32C: wrapperspb.Int64(crc32cAsInt64(digest.SHA256)),
		DataCrc32C:   wrapperspb.Int64(crc32cAsInt64(nil)),
	}

	response, err := s.Manager.KeyClient.AsymmetricSign(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("could not sign signer certificate: %v", err)
	}
	if crc32cAsInt64(response.GetSignature()) != response.GetSignatureCrc32C().GetValue() {
		return nil, errors.New("response corrupted in transit: signature_crc32c")
	}
	if request.GetDataCrc32C() != nil && !response.GetVerifiedDataCrc32C() {
		return nil, errors.New("request corrupted in transit: verified_data_crc32c")
	}
	if request.GetDigestCrc32C() != nil &&
		!response.GetVerifiedDigestCrc32C() {
		return nil, errors.New("request corrupted in transit: verified_digest_crc32c")
	}

	return response.GetSignature(), nil
}
