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
	"context"
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"

	"github.com/google/gce-tcb-verifier/sign/nonprod"
	styp "github.com/google/gce-tcb-verifier/sign/types"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"golang.org/x/exp/slices"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// FakeKmsServer responds to KMS RPCs with non-production signer values. Most metadata is elided
// since it is not used in this application.
type FakeKmsServer struct {
	kmspb.KeyManagementServiceServer

	Signer *nonprod.Signer

	createdKeyRings          map[string]*kmspb.KeyRing
	createdCryptoKeys        map[string]*kmspb.CryptoKey
	createdCryptoKeyVersions map[string]*kmspb.CryptoKeyVersion
}

type resource struct {
	project       string
	location      string
	keyring       string
	keyID         string
	versionNumber string
}

func (r *resource) String() string {
	prefix := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", r.project, r.location, r.keyring)
	if r.keyID == "" {
		return prefix
	}
	key := fmt.Sprintf("%s/cryptoKeys/%s", prefix, r.keyID)
	if r.versionNumber == "" {
		return key
	}
	return fmt.Sprintf("%s/cryptoKeyVersions/%s", key, r.versionNumber)
}

// parseResource provides the relevant information of a KMS resource name if it matches the expected
// naming convention. Returns nil if the name is illformed.
func parseResource(name string) *resource {
	pieces := strings.Split(name, "/")
	// Can either be
	// projects/*/locations/*/keyRings/*
	// projects/*/locations/*/keyRings/*/cryptoKeys/*
	// projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*
	if !slices.ContainsFunc([]int{6, 8, 10}, func(i int) bool { return i == len(pieces) }) {
		return nil
	}
	if pieces[0] != "projects" || pieces[1] == "" ||
		pieces[2] != "locations" || pieces[3] == "" ||
		pieces[4] != "keyRings" || pieces[5] == "" {
		return nil
	}
	if len(pieces) >= 8 && (pieces[6] != "cryptoKeys" || pieces[7] == "") {
		return nil
	}
	if len(pieces) == 10 && (pieces[8] != "cryptoKeyVersions" || pieces[9] == "") {
		return nil
	}
	result := &resource{
		project:  pieces[1],
		location: pieces[3],
		keyring:  pieces[5],
	}
	if len(pieces) >= 8 {
		result.keyID = pieces[7]
	}
	if len(pieces) == 10 {
		result.versionNumber = pieces[9]
	}
	return result
}

func keyFromKeyVersion(name string) (string, error) {
	r := parseResource(name)
	if r == nil {
		return "", fmt.Errorf("invalid resource name %q", name)
	}
	if r.versionNumber == "" {
		return "", fmt.Errorf("invalid cryptoKeyVersion name %q", name)
	}
	r.versionNumber = ""
	return r.String(), nil
}

func keyRingFromKeyVersion(name string) (string, error) {
	r := parseResource(name)
	if r == nil {
		return "", fmt.Errorf("invalid resource name %q", name)
	}
	if r.versionNumber == "" {
		return "", fmt.Errorf("invalid cryptoKeyVersion name %q", name)
	}
	r.keyID = ""
	r.versionNumber = ""
	return r.String(), nil
}

func keyInRing(name string, parent string) (bool, error) {
	rk := parseResource(name)
	if rk == nil {
		return false, fmt.Errorf("invalid resource name %q", name)
	}
	rp := parseResource(parent)
	if rp == nil {
		return false, fmt.Errorf("invalid resource name %q", parent)
	}
	return (rk.project == rp.project && rk.location == rp.location && rk.keyring == rp.keyring), nil
}

func keyVersionInKey(name string, parent string) (bool, error) {
	rk := parseResource(name)
	if rk == nil {
		return false, fmt.Errorf("invalid resource name %q", name)
	}
	rp := parseResource(parent)
	if rp == nil {
		return false, fmt.Errorf("invalid resource name %q", parent)
	}
	return (rk.project == rp.project && rk.location == rp.location && rk.keyring == rp.keyring && rk.keyID == rp.keyID), nil
}

// ListCryptoKeys returns the crypto keys under a key ring.
func (s *FakeKmsServer) ListCryptoKeys(_ context.Context, req *kmspb.ListCryptoKeysRequest) (*kmspb.ListCryptoKeysResponse, error) {
	seen := make(map[string]bool)
	result := &kmspb.ListCryptoKeysResponse{}
	for keyName, key := range s.createdCryptoKeys {
		seen[keyName] = true
		child, err := keyInRing(key.Name, req.GetParent())
		if err != nil {
			return nil, err
		}
		if child {
			result.CryptoKeys = append(result.CryptoKeys, key)
		}
	}
	for keyVersionName := range s.Signer.Keys {
		keyName, err := keyFromKeyVersion(keyVersionName)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[keyName]; ok {
			continue
		}
		seen[keyName] = true
		child, err := keyInRing(keyName, req.GetParent())
		if err != nil {
			return nil, err
		}
		if child {
			key := &kmspb.CryptoKey{
				Name: keyName,
			}
			result.CryptoKeys = append(result.CryptoKeys, key)
		}
	}
	result.TotalSize = int32(len(result.CryptoKeys))
	return result, nil
}

func (s *FakeKmsServer) listKeyVersionsUnder(parent string) ([]*kmspb.CryptoKeyVersion, error) {
	seen := make(map[string]bool)
	var result []*kmspb.CryptoKeyVersion
	for keyVersionName, keyVersion := range s.createdCryptoKeyVersions {
		seen[keyVersionName] = true
		child, err := keyVersionInKey(keyVersionName, parent)
		if err != nil {
			return nil, err
		}
		if child {
			result = append(result, keyVersion)
		}
	}
	for keyVersionName := range s.Signer.Keys {
		if _, ok := seen[keyVersionName]; ok {
			continue
		}
		child, err := keyVersionInKey(keyVersionName, parent)
		if err != nil {
			return nil, err
		}
		if child {
			keyVersion := &kmspb.CryptoKeyVersion{
				State: kmspb.CryptoKeyVersion_ENABLED,
				Name:  keyVersionName,
			}
			result = append(result, keyVersion)
		}
	}
	return result, nil
}

// ListCryptoKeyVersions returns the crypto key versions under a crypto key.
func (s *FakeKmsServer) ListCryptoKeyVersions(_ context.Context, req *kmspb.ListCryptoKeyVersionsRequest) (*kmspb.ListCryptoKeyVersionsResponse, error) {
	keyVersions, err := s.listKeyVersionsUnder(req.GetParent())
	if err != nil {
		return nil, err
	}
	result := &kmspb.ListCryptoKeyVersionsResponse{
		CryptoKeyVersions: keyVersions,
		TotalSize:         int32(len(keyVersions)),
	}
	return result, nil
}

// GetKeyRing returns the keyring object handle for a named keyring.
func (s *FakeKmsServer) GetKeyRing(_ context.Context, req *kmspb.GetKeyRingRequest) (*kmspb.KeyRing, error) {
	for keyVersionName := range s.Signer.Keys {
		keyRingName, err := keyRingFromKeyVersion(keyVersionName)
		if err != nil {
			return nil, err
		}
		if req.Name == keyRingName {
			return &kmspb.KeyRing{
				Name: keyRingName,
			}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "not found")
}

func (s *FakeKmsServer) getCryptoKeyByName(name string) (*kmspb.CryptoKey, error) {
	if s.createdCryptoKeys != nil {
		if key, ok := s.createdCryptoKeys[name]; ok {
			return key, nil
		}
	}
	for keyVersionName := range s.Signer.Keys {
		keyName, err := keyFromKeyVersion(keyVersionName)
		if err != nil {
			return nil, err
		}
		if keyName == name {
			return &kmspb.CryptoKey{
				Name:    keyName,
				Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
				VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
					Algorithm:       kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
					ProtectionLevel: kmspb.ProtectionLevel_HSM,
				},
			}, nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "crypto key %s not found", name)
}

// GetCryptoKey returns the object handle for a named crypto key.
func (s *FakeKmsServer) GetCryptoKey(_ context.Context, req *kmspb.GetCryptoKeyRequest) (key *kmspb.CryptoKey, err error) {
	return s.getCryptoKeyByName(req.Name)
}

// GetCryptoKeyVersion returns the object handle for a named crypto key version.
func (s *FakeKmsServer) GetCryptoKeyVersion(_ context.Context, req *kmspb.GetCryptoKeyVersionRequest) (key *kmspb.CryptoKeyVersion, err error) {
	if s.createdCryptoKeyVersions != nil {
		if keyVersion, ok := s.createdCryptoKeyVersions[req.Name]; ok {
			return keyVersion, nil
		}
	}
	if s.Signer.Keys == nil || s.Signer.Keys[req.Name] == nil {
		return nil, status.Error(codes.NotFound, "not found")
	}
	return &kmspb.CryptoKeyVersion{
		Name:  req.Name,
		State: kmspb.CryptoKeyVersion_ENABLED,
	}, nil
}

// GetPublicKey returns the named crypto key version's public key.
func (s *FakeKmsServer) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	pem, err := s.Signer.PublicKey(ctx, req.Name)
	if err != nil {
		return nil, err
	}

	return &kmspb.PublicKey{
		Name:      req.Name,
		Pem:       string(pem),
		PemCrc32C: &wrapperspb.Int64Value{Value: int64(crc32.Checksum(pem, crc32.MakeTable(crc32.Castagnoli)))},
		Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
	}, nil
}

// CreateKeyRing creates a key ring and returns its object handle.
func (s *FakeKmsServer) CreateKeyRing(_ context.Context, req *kmspb.CreateKeyRingRequest) (keyring *kmspb.KeyRing, err error) {
	if _, ok := s.createdKeyRings[req.GetParent()]; ok {
		return nil, status.Errorf(codes.AlreadyExists, "keyRing %s already exists", req.GetParent())
	}
	if s.createdKeyRings == nil {
		s.createdKeyRings = make(map[string]*kmspb.KeyRing)
	}
	keyRing := req.GetKeyRing()
	s.createdKeyRings[req.GetParent()] = keyRing
	return keyRing, nil
}

func (s *FakeKmsServer) registerCryptoKey(req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	if s.createdCryptoKeys == nil {
		s.createdCryptoKeys = make(map[string]*kmspb.CryptoKey)
	}
	keyName := req.GetParent() + "/cryptoKeys/" + req.GetCryptoKeyId()
	if _, ok := s.createdCryptoKeys[keyName]; ok {
		return nil, status.Errorf(codes.AlreadyExists, "crypto key %s already exists", keyName)
	}
	key := req.GetCryptoKey()
	key.Name = keyName

	if key.GetPurpose() != kmspb.CryptoKey_ASYMMETRIC_SIGN {
		return nil, fmt.Errorf("unsupported purpose %v", key.GetPurpose())
	}
	if key.VersionTemplate == nil {
		return nil, fmt.Errorf("no version template")
	}
	vtpml := key.GetVersionTemplate()
	pl := vtpml.GetProtectionLevel()
	if pl != kmspb.ProtectionLevel_HSM && pl != kmspb.ProtectionLevel_SOFTWARE {
		return nil, fmt.Errorf("unsupported protection level %v", pl)
	}
	if vtpml.GetAlgorithm() != kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256 {
		return nil, fmt.Errorf("unsupported algorithm %v", key.GetVersionTemplate().GetAlgorithm())
	}
	s.createdCryptoKeys[keyName] = key
	return key, nil
}

// CreateCryptoKey creates a crypto key and returns its object handle.
func (s *FakeKmsServer) CreateCryptoKey(_ context.Context, req *kmspb.CreateCryptoKeyRequest) (key *kmspb.CryptoKey, err error) {
	key, err = s.registerCryptoKey(req)
	if err != nil {
		return nil, err
	}
	if _, err := s.makeVersionUnderCryptoKey(key); err != nil {
		return nil, fmt.Errorf("could not create initial key version: %v", err)
	}
	return key, nil
}

func (s *FakeKmsServer) maxVersion(keyName string) (int, error) {
	versions, err := s.listKeyVersionsUnder(keyName)
	if err != nil {
		return 0, err
	}
	var maxVersion int
	for _, keyVersion := range versions {
		version, err := strconv.Atoi(parseResource(keyVersion.Name).versionNumber)
		if err != nil {
			return 0, fmt.Errorf("could not parse version number %s: %v", keyVersion.Name, err)
		}
		if version > maxVersion {
			maxVersion = version
		}
	}
	return maxVersion, nil
}

func (s *FakeKmsServer) makeVersionUnderCryptoKey(key *kmspb.CryptoKey) (*kmspb.CryptoKeyVersion, error) {
	counter, err := s.maxVersion(key.Name)
	if err != nil {
		return nil, err
	}
	keyVersionName := fmt.Sprintf("%s/cryptoKeyVersions/%d", key.Name, counter+1)
	if _, ok := s.createdCryptoKeyVersions[keyVersionName]; ok {
		return nil, status.Errorf(codes.AlreadyExists, "key version %s already exists", keyVersionName)
	}
	if s.Signer.Keys != nil && s.Signer.Keys[keyVersionName] != nil {
		return nil, status.Errorf(codes.AlreadyExists, "key version %s already exists", keyVersionName)
	}
	if s.createdCryptoKeyVersions == nil {
		s.createdCryptoKeyVersions = make(map[string]*kmspb.CryptoKeyVersion)
	}

	template := key.GetVersionTemplate()
	if template.GetAlgorithm() != kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256 {
		return nil, fmt.Errorf("unsupported algorithm %v", template.GetAlgorithm())
	}

	keyVersion := &kmspb.CryptoKeyVersion{
		Name:            keyVersionName,
		Algorithm:       template.GetAlgorithm(),
		ProtectionLevel: template.GetProtectionLevel(),
		State:           kmspb.CryptoKeyVersion_ENABLED,
	}
	s.createdCryptoKeyVersions[keyVersionName] = keyVersion

	isRoot := template.GetProtectionLevel() == kmspb.ProtectionLevel_HSM
	if isRoot {
		if _, err := s.Signer.GenerateRootKey(keyVersionName); err != nil {
			return nil, err
		}
	} else {
		if _, err := s.Signer.GenerateSigningKey(keyVersionName); err != nil {
			return nil, err
		}
	}
	return keyVersion, nil
}

// CreateCryptoKeyVersion creates a new crypto key version under a given crypto key.
func (s *FakeKmsServer) CreateCryptoKeyVersion(_ context.Context, req *kmspb.CreateCryptoKeyVersionRequest) (key *kmspb.CryptoKeyVersion, err error) {
	ck, err := s.getCryptoKeyByName(req.GetParent())
	if err != nil {
		return nil, err
	}
	return s.makeVersionUnderCryptoKey(ck)
}

// AsymmetricSign signs a given digest with a named crypto key version's private key.
func (s *FakeKmsServer) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	if req.DataCrc32C == nil {
		return nil, fmt.Errorf("no data crc32c")
	}
	if req.DigestCrc32C == nil {
		return nil, fmt.Errorf("no digest crc32c")
	}
	dataCrc32 := crc32.Checksum(req.GetData(), crc32.MakeTable(crc32.Castagnoli))
	if uint32(req.GetDataCrc32C().Value) != dataCrc32 {
		return nil, fmt.Errorf("data crc32c mismatch")
	}

	digest := req.Digest
	if _, ok := digest.Digest.(*kmspb.Digest_Sha256); !ok {
		return nil, fmt.Errorf("unsupported digest: %v", digest)
	}
	digestCrc32 := crc32.Checksum(digest.GetSha256(), crc32.MakeTable(crc32.Castagnoli))
	if uint32(req.GetDigestCrc32C().Value) != digestCrc32 {
		return nil, fmt.Errorf("digest crc32c mismatch")
	}

	r := parseResource(req.Name)
	if r == nil {
		return nil, fmt.Errorf("invalid resource name %s", req.Name)
	}
	r.versionNumber = ""

	ck, err := s.getCryptoKeyByName(r.String())
	if err != nil {
		return nil, fmt.Errorf("could not get crypto key %s: %v", r.String(), err)
	}
	if ck.GetVersionTemplate().GetAlgorithm() != kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256 {
		return nil, fmt.Errorf("unsupported algorithm %v", ck.GetVersionTemplate().GetAlgorithm())
	}

	keyVersionName := req.Name

	out, err := s.Signer.Sign(ctx, keyVersionName, styp.Digest{SHA256: digest.GetSha256()}, nonprod.DefaultOpts())
	if err != nil {
		return nil, err
	}
	return &kmspb.AsymmetricSignResponse{
		Signature:            out,
		SignatureCrc32C:      &wrapperspb.Int64Value{Value: int64(crc32.Checksum(out, crc32.MakeTable(crc32.Castagnoli)))},
		VerifiedDigestCrc32C: true,
		VerifiedDataCrc32C:   true,
	}, nil
}

// DestroyCryptoKeyVersion marks the named crypto key version for destruction.
// We don't care if the key doesn't exist. Don't error.
func (s *FakeKmsServer) DestroyCryptoKeyVersion(_ context.Context, req *kmspb.DestroyCryptoKeyVersionRequest) (key *kmspb.CryptoKeyVersion, err error) {
	if s.createdCryptoKeyVersions != nil {
		delete(s.createdCryptoKeyVersions, req.Name)
	}
	if s.Signer.Keys != nil {
		delete(s.Signer.Keys, req.Name)
	}
	return &kmspb.CryptoKeyVersion{
		Name:  req.Name,
		State: kmspb.CryptoKeyVersion_DESTROYED,
	}, nil
}
