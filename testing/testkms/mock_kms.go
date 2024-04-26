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

package testkms

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"net"
	"testing"

	"context"

	styp "github.com/google/gce-tcb-verifier/sign/types"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"

	iampb "cloud.google.com/go/iam/apiv1/iampb"

	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// KeyManagementServer represents a crude mock object that implements the Cloud KMS client interface
// for testing KMS interactions. There is no Cloud KMS-owned mock implementation for others to use,
// so we just do what we can here.
type KeyManagementServer struct {
	// Embed for forward compatibility.
	// Tests will keep working if more methods are added
	// in the future.
	kmspb.KeyManagementServiceServer

	// Reqs captures all requests sent in order.
	Reqs []proto.Message

	// If set, all calls return this error.
	Err error

	// Specialized responses for non-*Response return values
	UpdateCryptoKeyPrimaryVersionResp *kmspb.CryptoKey
	CreateCryptoKeyResp               map[string]*kmspb.CryptoKey
	CreateCryptoKeyVersionResp        map[string]*kmspb.CryptoKeyVersion
	DestroyCryptoKeyVersionResp       map[string]*kmspb.CryptoKeyVersion
	GetCryptoKeyResp                  map[string]*kmspb.CryptoKey
	GetCryptoKeyVersionResp           map[string]*kmspb.CryptoKeyVersion
	AsymmetricSignResp                map[string]*kmspb.AsymmetricSignResponse
	ListCryptoKeyVersionsResp         map[string]*kmspb.ListCryptoKeyVersionsResponse

	CreateKeyRingErr   error
	CreateCryptoKeyErr map[string]error

	// Resps represents responses to return if err == nil, and not special-cased by above fields.
	Resps []proto.Message
}

// Clear resets all per-test requests and responses back to empty.
func (s *KeyManagementServer) Clear() {
	s.Reqs = nil
	s.UpdateCryptoKeyPrimaryVersionResp = nil
	s.CreateCryptoKeyResp = nil
	s.CreateCryptoKeyVersionResp = nil
	s.DestroyCryptoKeyVersionResp = nil
	s.GetCryptoKeyResp = nil
	s.AsymmetricSignResp = nil
	s.Resps = nil
	s.CreateCryptoKeyErr = nil
	s.ListCryptoKeyVersionsResp = nil
	s.Err = nil

	s.CreateKeyRingErr = nil
	s.CreateCryptoKeyErr = nil
}

// ListCryptoKeys returns the crypto keys under a key ring.
func (s *KeyManagementServer) ListCryptoKeys(context.Context, *kmspb.ListCryptoKeysRequest) (*kmspb.ListCryptoKeysResponse, error) {
	for _, r := range s.Resps {
		resp, ok := r.(*kmspb.ListCryptoKeysResponse)
		if ok {
			return resp, nil
		}
	}
	return nil, fmt.Errorf("no ListCryptoKeysResponse")
}

// ListCryptoKeyVersions returns the crypto key versions under a crypto key.
func (s *KeyManagementServer) ListCryptoKeyVersions(_ context.Context, req *kmspb.ListCryptoKeyVersionsRequest) (*kmspb.ListCryptoKeyVersionsResponse, error) {
	if len(s.ListCryptoKeyVersionsResp) > 0 {
		resp, ok := s.ListCryptoKeyVersionsResp[req.GetParent()]
		if ok {
			return resp, nil
		}
	}
	return nil, fmt.Errorf("no ListCryptoKeyVersionsResponse for %q", req.GetParent())
}

// GetKeyRing returns the first KeyRing response in the mock's list of responses.
func (s *KeyManagementServer) GetKeyRing(context.Context, *kmspb.GetKeyRingRequest) (*kmspb.KeyRing, error) {
	for _, resp := range s.Resps {
		kr, ok := resp.(*kmspb.KeyRing)
		if ok {
			return kr, nil
		}
	}
	return nil, fmt.Errorf("keyring not found")
}

// GetCryptoKey returns a CryptoKey object from its resource name.
func (s *KeyManagementServer) GetCryptoKey(_ context.Context, req *kmspb.GetCryptoKeyRequest) (key *kmspb.CryptoKey, err error) {
	var ok bool
	if len(s.GetCryptoKeyResp) > 0 {
		key, ok = s.GetCryptoKeyResp[req.Name]
	}
	if !ok {
		return nil, fmt.Errorf("GetCryptoKey: no key named %q", req.Name)
	}
	if key == nil {
		return nil, status.Errorf(codes.PermissionDenied, "synthetic error for key %q", req.Name)
	}
	return key, nil
}

// GetCryptoKeyVersion returns a CryptoKeyVersion object from its resource name.
func (s *KeyManagementServer) GetCryptoKeyVersion(_ context.Context, req *kmspb.GetCryptoKeyVersionRequest) (key *kmspb.CryptoKeyVersion, err error) {
	var ok bool
	if len(s.GetCryptoKeyVersionResp) > 0 {
		key, ok = s.GetCryptoKeyVersionResp[req.Name]
	}
	if !ok {
		return nil, fmt.Errorf("GetCryptoKeyVersion: no key named %q", req.Name)
	}
	if key == nil {
		return nil, status.Errorf(codes.PermissionDenied, "synthetic error for key %q", req.Name)
	}
	return key, nil
}

// GetPublicKey returns the name key's public key.
func (s *KeyManagementServer) GetPublicKey(_ context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	for _, r := range s.Resps {
		resp, ok := r.(*kmspb.PublicKey)
		if !ok || r == nil || req.Name != resp.Name {
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("public key: no key named %q", req.Name)
}

// CreateKeyRing creates a new keyring and returns its object handle.
func (s *KeyManagementServer) CreateKeyRing(context.Context, *kmspb.CreateKeyRingRequest) (keyring *kmspb.KeyRing, err error) {
	for _, r := range s.Resps {
		resp, ok := r.(*kmspb.KeyRing)
		if ok {
			keyring = resp
			break
		}
	}
	return keyring, s.CreateKeyRingErr
}

// CreateCryptoKey creates a new crypto key and returns its object handle.
func (s *KeyManagementServer) CreateCryptoKey(_ context.Context, req *kmspb.CreateCryptoKeyRequest) (key *kmspb.CryptoKey, err error) {
	var ok bool
	if len(s.CreateCryptoKeyResp) > 0 {
		key, ok = s.CreateCryptoKeyResp[req.GetCryptoKeyId()]
	}
	if len(s.CreateCryptoKeyErr) > 0 {
		err = s.CreateCryptoKeyErr[req.GetCryptoKeyId()]
	}
	if !ok && err != nil {
		return nil, fmt.Errorf("could not create key for %q: %w", req.GetCryptoKeyId(), err)
	}

	return key, err
}

// CreateCryptoKeyVersion creates a new crypto key version and returns its object handle.
func (s *KeyManagementServer) CreateCryptoKeyVersion(_ context.Context, req *kmspb.CreateCryptoKeyVersionRequest) (key *kmspb.CryptoKeyVersion, err error) {
	var ok bool
	if len(s.CreateCryptoKeyVersionResp) > 0 {
		key, ok = s.CreateCryptoKeyVersionResp[req.GetParent()]
	}
	if !ok {
		return nil, fmt.Errorf("could not create key version for %q", req.GetParent())
	}
	return key, nil
}

// AsymmetricSign uses an asymmetric key's private key to sign a given digest.
func (s *KeyManagementServer) AsymmetricSign(_ context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	resp, ok := s.AsymmetricSignResp[hex.EncodeToString(req.Digest.GetSha256())]
	if !ok {
		return nil, fmt.Errorf("no signature entry for %v", req.Digest.GetSha256())
	}
	return resp, nil
}

// DestroyCryptoKeyVersion marks a named crypto key version for destruction.
func (s *KeyManagementServer) DestroyCryptoKeyVersion(_ context.Context, req *kmspb.DestroyCryptoKeyVersionRequest) (key *kmspb.CryptoKeyVersion, err error) {
	var ok bool
	if len(s.DestroyCryptoKeyVersionResp) > 0 {
		key, ok = s.DestroyCryptoKeyVersionResp[req.Name]
	}
	if !ok {
		return nil, fmt.Errorf("could not destroy key version %q", req.Name)
	}
	return key, nil
}

// InitGrpcKmsTestServers creates a server for the given KMS and IAMPolicy server implementations
// and returns gRPC connections that can be used to make clients.
func InitGrpcKmsTestServers(t testing.TB, m kmspb.KeyManagementServiceServer, i iampb.IAMPolicyServer) option.ClientOption {
	serv := grpc.NewServer()
	kmspb.RegisterKeyManagementServiceServer(serv, m)
	iampb.RegisterIAMPolicyServer(serv, i)
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("could not listen for test grpc server: %v", err)
	}
	go serv.Serve(lis)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("could not create new client for test KMS server: %v", err)
	}
	return option.WithGRPCConn(conn)
}

// IAMPolicyServer is a mock IAM service client server that only deals with no-op policies.
type IAMPolicyServer struct {
	iampb.IAMPolicyServer
}

// SetIamPolicy returns the given policy.
func (*IAMPolicyServer) SetIamPolicy(_ context.Context, in *iampb.SetIamPolicyRequest) (*iampb.Policy, error) {
	return in.GetPolicy(), nil
}

// AddPKResponse extends s.Resps with the expected response object for a GetPublicKey request using
// a key in the given signer. Failures use `t` to indicate failure instead of returning an error.
func (s *KeyManagementServer) AddPKResponse(keyVersionName string, signer styp.Signer, t *testing.T) {
	pembytes, err := signer.PublicKey(context.Background(), keyVersionName)
	if err != nil {
		t.Fatalf("AddPKResponse: %v", err)
	}
	s.Resps = append(s.Resps, &kmspb.PublicKey{
		Name: keyVersionName,
		Pem:  string(pembytes),
	})
}

// AddKmsSignatureResponse stores an AsymmetricSign response for the given digest.
func (s *KeyManagementServer) AddKmsSignatureResponse(toHashAndSign, signature []byte) {
	if s.AsymmetricSignResp == nil {
		s.AsymmetricSignResp = make(map[string]*kmspb.AsymmetricSignResponse)
	}

	toSign := sha256.Sum256(toHashAndSign)
	crc := crc32.Checksum(signature, crc32.MakeTable(crc32.Castagnoli))
	s.AsymmetricSignResp[hex.EncodeToString(toSign[:])] = &kmspb.AsymmetricSignResponse{
		Signature:            signature,
		SignatureCrc32C:      &wrapperspb.Int64Value{Value: int64(crc)},
		VerifiedDigestCrc32C: true,
		VerifiedDataCrc32C:   true,
	}
}
