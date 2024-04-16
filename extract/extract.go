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

// Package extract provides endorsement extraction logic to access cached information available from
// either an attestation report or an event logger. Event logs may point to downloadable URIs and/or
// local UEFI variables, so extraction ought to be done by the lead attester to include as evidence
// to an attestation verification service.
package extract

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/google/gce-tcb-verifier/extract/extractsev"
	"github.com/google/gce-tcb-verifier/sev"
	"github.com/google/gce-tcb-verifier/verify"
	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	tpmpb "github.com/google/go-tpm-tools/proto/attest"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/proto"
)

var (
	// ErrOptionsNil is returned when an Options is needed but is nil.
	ErrOptionsNil = errors.New("extract options is nil")
	// ErrGetterNil is returned when a Getter is needed but is nil.
	ErrGetterNil = errors.New("getter is nil")
	// ErrQuoteNil is returned when a Quote is needed but is nil.
	ErrQuoteNil = errors.New("quote is nil")
	// ErrUnknownFormat is returned when an attestation file cannot be decoded from any of the
	// supported forms.
	ErrUnknownFormat = errors.New("unknown attestation format")
)

const (
	// GCEFirmwareManufacturer is the expected FirmwareManufacturer value in an SP800-155 Event3 event
	// on a GCE VM.
	GCEFirmwareManufacturer    = "GCE"
	defaultEfiVarMountLocation = "/sys/firmware/efi/efivars"
)

// QuoteProvider provides a raw quote within a trusted execution environment.
type QuoteProvider interface {
	// IsSupported returns whether the kernel supports this implementation.
	IsSupported() bool
	// GetRawQuote returns a raw report with the default privilege level.
	GetRawQuote(reportData [64]byte) ([]uint8, error)
}

// HTTPSGetter provides a Get function to return the body of an https GET request.
type HTTPSGetter interface {
	Get(url string) ([]byte, error)
}

// Options provides configuration for RIM extraction logic.
type Options struct {
	Provider         QuoteProvider
	Getter           HTTPSGetter
	EventLogLocation string
	// Quote is any of the supported formats. If empty, the Provider will be used to get a quote.
	Quote []byte
}

// FromEventLog returns the contents of a UEFI variable that an SP 800-155 event points to.
func (opts *Options) fromEventLog() ([]byte, error) {
	return nil, fmt.Errorf("unimplemented")
}

func fromSevSnpAttestationProto(at *spb.Attestation) ([]byte, string, error) {
	if out, err := extractsev.FromAttestation(at); err == nil {
		return out, "", nil
	}
	meas := at.GetReport().GetMeasurement()
	return nil, extractsev.GceTcbObjectName(sev.GCEUefiFamilyID, meas), nil
}

// Attestation will try to deserialize a given attestation in any of the supported formats and
// return it packaged in the most general format.
func Attestation(quote []byte) (*tpmpb.Attestation, error) {
	if len(quote) == 0 {
		return nil, ErrQuoteNil
	}
	tpmat := &tpmpb.Attestation{}
	if err := proto.Unmarshal(quote, tpmat); err == nil {
		return tpmat, nil
	}

	// The Report Proto can be deserialized as an Attestation proto with adverse effect, so disallow
	// a bad measurement deserialization.
	sev := &spb.Attestation{}
	if err := proto.Unmarshal(quote, sev); err == nil && len(sev.GetReport().GetMeasurement()) == abi.MeasurementSize {
		tpmat.TeeAttestation = &tpmpb.Attestation_SevSnpAttestation{SevSnpAttestation: sev}
		return tpmat, nil
	}
	sev.Report = &spb.Report{}
	if err := proto.Unmarshal(quote, sev.Report); err == nil {
		sev.CertificateChain = nil
		tpmat.TeeAttestation = &tpmpb.Attestation_SevSnpAttestation{SevSnpAttestation: sev}
		return tpmat, nil
	}

	// TODO: Try the TDX quote proto.

	// If hex- or base64-encoded, decode it.
	if decoded, err := hex.DecodeString(string(quote)); err == nil {
		quote = decoded
	} else if decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(quote))); err == nil {
		quote = decoded
	}

	// Attempt to decode as a raw SEV-SNP attestation.
	// Get the raw quote and try to extract from the certificates.
	if at, err := abi.ReportCertsToProto(quote); err == nil {
		tpmat.TeeAttestation = &tpmpb.Attestation_SevSnpAttestation{SevSnpAttestation: at}
		return tpmat, nil
	}
	// Attempt to decode as just the SEV-SNP certificate table.
	certs := new(abi.CertTable)
	if err := certs.Unmarshal(quote); err == nil {
		sev.Report = &spb.Report{Measurement: []byte{0}}
		sev.CertificateChain = certs.Proto()
		tpmat.TeeAttestation = &tpmpb.Attestation_SevSnpAttestation{SevSnpAttestation: sev}
		return tpmat, nil
	}
	return nil, ErrUnknownFormat
}

func (opts *Options) fromQuote(quote []byte) (endorsement []byte, objectName string, err error) {
	// If an attestation from go-tpm-tools, try to extract the endorsement from the TEE attestation.
	tpmat, err := Attestation(quote)
	if err != nil {
		return nil, "", err
	}
	switch at := tpmat.TeeAttestation.(type) {
	case *tpmpb.Attestation_SevSnpAttestation:
		return fromSevSnpAttestationProto(at.SevSnpAttestation)
	}
	// TODO: Otherwise try the TDX quote.
	return nil, "", ErrUnknownFormat
}

// Endorsement will try to find the UEFI endorsement from local context.
func Endorsement(opts *Options) (out []byte, err error) {
	if opts == nil {
		return nil, ErrOptionsNil
	}

	var quote, endorsement []byte
	var objectName string
	var evErr, quoteErr, internetErr error
	// If the verbatim quote is provided, try that first.
	endorsement, objectName, quoteErr = opts.fromQuote(opts.Quote)
	if quoteErr == nil && len(endorsement) > 0 {
		return endorsement, nil
	}

	// Then try the event logger.
	if opts.EventLogLocation != "" {
		out, evErr = opts.fromEventLog()
		if evErr == nil {
			return out, nil
		}
	}

	// Then try obtaining a quote for its auxblob or measurement if the objectName is not known.
	if opts.Provider != nil && objectName == "" {
		var zeroes [64]byte
		quote, quoteErr = opts.Provider.GetRawQuote(zeroes)
		if quoteErr != nil {
			return nil, quoteErr
		}
		endorsement, objectName, quoteErr = opts.fromQuote(quote)
		if quoteErr != nil {
			return nil, quoteErr
		}
		if len(endorsement) > 0 {
			return endorsement, nil
		}
	}

	// Then try the internet.
	if opts.Getter == nil {
		internetErr = ErrGetterNil
	} else {
		endorsement, internetErr = opts.Getter.Get(verify.GceTcbURL(objectName))
		if internetErr == nil {
			return endorsement, nil
		}
	}
	return nil, multierr.Combine(evErr, quoteErr, internetErr)
}
