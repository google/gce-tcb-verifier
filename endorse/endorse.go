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

// Package endorse defines functions for producing and signing golden measurements of a UEFI.
package endorse

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"time"

	"github.com/google/gce-tcb-verifier/keys"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/gce-tcb-verifier/sev"
	styp "github.com/google/gce-tcb-verifier/sign/types"
	"github.com/google/gce-tcb-verifier/timeproto"
	"google.golang.org/protobuf/proto"
)

// ErrNoContext is returned when a function requires an endorse.Context is needed but is missing
// from the context.
var ErrNoContext = errors.New("no endorse context found")

// Context encapsulates all information needed to generate an endorsement for a UEFI
// binary.
type Context struct {
	// SevSnp is an optional request for endorsing SEV-SNP-specific information for the image.
	SevSnp *sev.SnpEndorsementRequest
	// Image is the full contents of the UEFI binary to endorse.
	Image  []byte
	ClSpec uint64
	// Commit is the git commit hash that corresponds to the ClSpec.
	Commit []byte
	// CandidateName is the name of the candidate from which the image was built.
	CandidateName string
	// ReleaseBranch is the name of the piper branch on which the image was build.
	ReleaseBranch string
	// Timestamp is what time will be reported in the golden measurement document.
	Timestamp       time.Time
	VCS             VersionControl
	CommitFinalizer CommitFinalizer
	// Fields used by VCS when committing an endorsement.
	CommitRetries int
	// OutDir is the VCS-root-relative location in which to write the endorsement files.
	OutDir string
	// DryRun true means that no endorsements will get written to version control or finalized.
	DryRun          bool
	MeasurementOnly bool
	// SnapshotDir is the VCS-root-relative location in which to write the snapshot files.
	// Snapshotting is a different VCS commitment method that submits the firmware and its signature
	// to the VCS with related paths. This is in addition to the manifest method to allow for older
	// releases to still get signatures in a way the VMM can parse.
	SnapshotDir string
	// SnapshotToHead is true if the snapshot should be written to HEAD instead of the release branch.
	// This is an interim solution until the firmware is entirely in its own separately released
	// package.
	SnapshotToHead bool
	// ImageName is the path under SnapshotDir to write the firmware and its endorsement.
	ImageName string
}

type endorseKeyType struct{}

var endorseKey endorseKeyType

// NewContext returns the context extended with the given endorse.Context
func NewContext(ctx context.Context, ec *Context) context.Context {
	return context.WithValue(ctx, endorseKey, ec)
}

// FromContext returns the endorse.Context in the context or an error.
func FromContext(ctx context.Context) (*Context, error) {
	if ec, ok := ctx.Value(endorseKey).(*Context); ok {
		return ec, nil
	}
	return nil, ErrNoContext
}

// GoldenMeasurement produces the unsigned GoldenMeasurement for a given request and all
// GCE-supported vCPU counts.
func GoldenMeasurement(ctx context.Context) (*epb.VMGoldenMeasurement, error) {
	ec, err := FromContext(ctx)
	if err != nil {
		return nil, err
	}
	goldenBuilder := &epb.VMGoldenMeasurement{}

	// Track the UEFI digest.
	digest := sha512.Sum384(ec.Image)
	goldenBuilder.Digest = digest[:]

	if ec.SevSnp != nil {
		snp, err := sev.UnsignedSnp(ec.Image, ec.SevSnp)
		if err != nil {
			return nil, err
		}
		goldenBuilder.SevSnp = snp
		goldenBuilder.ClSpec = ec.ClSpec
		goldenBuilder.Commit = ec.Commit
		return goldenBuilder, nil
	}
	return nil, errors.New("no supported technology specified in signing request")
}

// SignDoc returns a signed endorsement of a given golden measurement.
func SignDoc(ctx context.Context, doc *epb.VMGoldenMeasurement) (*epb.VMLaunchEndorsement, error) {
	c, err := keys.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	if c.CA == nil {
		return nil, keys.ErrNoCertificateAuthority
	}
	if c.Signer == nil {
		return nil, keys.ErrNoSigner
	}
	ec, err := FromContext(ctx)
	if err != nil {
		return nil, err
	}
	keyVersionName, err := c.CA.PrimarySigningKeyVersion(ctx)
	if err != nil {
		return nil, err
	}
	cert, err := c.CA.Certificate(ctx, keyVersionName)
	if err != nil {
		return nil, err
	}
	caBundle, err := c.CA.CABundle(ctx, keyVersionName)
	if err != nil {
		return nil, err
	}
	doc.Cert = cert
	doc.CaBundle = caBundle
	doc.Timestamp = timeproto.To(ec.Timestamp)
	toSign, err := proto.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("could not serialize golden measurement: %w", err)
	}
	digest := sha256.Sum256(toSign)
	signature, err := c.Signer.Sign(ctx, keyVersionName, styp.Digest{SHA256: digest[:]},
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		})
	if err != nil {
		return nil, fmt.Errorf("could not sign golden measurement: %w", err)
	}
	return &epb.VMLaunchEndorsement{
		SerializedUefiGolden: toSign,
		Signature:            signature,
	}, nil
}

func outputSevMeasurement(ec *Context, snp *epb.VMSevSnp) {
	if ec.SevSnp.LaunchVmsas != 0 {
		fmt.Println(hex.EncodeToString(snp.Measurements[ec.SevSnp.LaunchVmsas]))
		return
	}
	for vcpus, meas := range snp.Measurements {
		fmt.Printf("%d %s\n", vcpus, hex.EncodeToString(meas))
	}
}

// Ovmf calculates the golden measurement of the given OVMF image, signs a document with the
// measurement and associated metadata, submits it, and performs finalization.
func Ovmf(ctx context.Context) error {
	ec, err := FromContext(ctx)
	if err != nil {
		return err
	}
	golden, err := GoldenMeasurement(ctx)
	if err != nil {
		return fmt.Errorf("golden measurement calculation error: %s", err)
	}
	if ec.MeasurementOnly {
		hasSevSnp := golden.SevSnp != nil
		if hasSevSnp {
			outputSevMeasurement(ec, golden.SevSnp)
		}
		return nil
	}
	endorsement, err := SignDoc(ctx, golden)
	if err != nil {
		return fmt.Errorf("could not sign endorsement: %v", err)
	}

	if ec.VCS != nil {
		resp, err := commitEndorsement(ctx, endorsement)
		if err != nil {
			return err
		}
		if ec.CommitFinalizer != nil && !ec.DryRun {
			return ec.CommitFinalizer.Finalize(ctx, resp)
		}
	}
	return nil
}
