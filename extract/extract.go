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
	"os"

	"github.com/google/gce-tcb-verifier/eventlog"
	exel "github.com/google/gce-tcb-verifier/extract/eventlog"
	"github.com/google/gce-tcb-verifier/extract/extractsev"
	"github.com/google/gce-tcb-verifier/extract/extracttdx"
	"github.com/google/gce-tcb-verifier/sev"
	"github.com/google/gce-tcb-verifier/verify"
	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify/trust"
	tabi "github.com/google/go-tdx-guest/abi"
	tpb "github.com/google/go-tdx-guest/proto/tdx"
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
	// ErrEventLogPathEmpty is returned when the event log path in Options is empty.
	ErrEventLogPathEmpty = errors.New("event log path is empty")
)

const (
	// GCEFirmwareManufacturer is the expected FirmwareManufacturer value in an SP800-155 Event3 event
	// on a GCE VM.
	GCEFirmwareManufacturer = "Google, Inc."
)

// QuoteProvider provides a raw quote within a trusted execution environment.
type QuoteProvider interface {
	// IsSupported returns whether the kernel supports this implementation.
	IsSupported() bool
	// GetRawQuote returns a raw report with the default privilege level.
	GetRawQuote(reportData [64]byte) ([]uint8, error)
}

// Options provides configuration for RIM extraction logic.
type Options struct {
	Provider             QuoteProvider
	Getter               trust.HTTPSGetter
	FirmwareManufacturer string
	EventLogLocation     string
	UEFIVariableReader   exel.VariableReader
	// Quote is any of the supported formats. If empty, the Provider will be used to get a quote.
	Quote      []byte
	ForceFetch bool
}

// DefaultOptions returns the default options for RIM extraction.
func DefaultOptions() *Options {
	lopts := exel.DefaultLocateOptions()
	return &Options{
		// Provider:             &client.TEEQuoteProvider{},
		Getter:               lopts.Getter,
		FirmwareManufacturer: GCEFirmwareManufacturer,
		EventLogLocation:     "/sys/kernel/security/tpm0/binary_bios_measurements",
		UEFIVariableReader:   lopts.UEFIVariableReader,
		Quote:                []byte{},
	}
}

func elFromFile(path string) (*eventlog.CryptoAgileLog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read event log file %q: %v", path, err)
	}
	defer f.Close()
	el := &eventlog.CryptoAgileLog{}
	if err := el.Unmarshal(f); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event log file %q: %v", path, err)
	}
	return el, nil
}

// fromEventLog returns the contents of a UEFI variable that an SP 800-155 event points to.
func (opts *Options) fromEventLog() ([]byte, error) {
	if opts == nil {
		return nil, ErrOptionsNil
	}
	if opts.EventLogLocation == "" {
		return nil, ErrEventLogPathEmpty
	}

	el, err := elFromFile(opts.EventLogLocation)
	if err != nil {
		return nil, err
	}
	evts := exel.RIMEventsFromEventLog(el)
	locopts := &exel.LocateOptions{
		Getter:             opts.Getter,
		UEFIVariableReader: opts.UEFIVariableReader,
	}
	for _, evts := range [][]*eventlog.SP800155Event3{
		// Raw data takes precedence over UEFI variables.
		evts[eventlog.RIMLocationRaw],
		// UEFI variables take precedence over local device paths.
		evts[eventlog.RIMLocationVariable],
		// UEFI local device paths take precedence over URIs.
		evts[eventlog.RIMLocationLocal],
		// Finally reach out to the network.
		evts[eventlog.RIMLocationURI]} {
		for _, evt := range evts {
			if len(opts.FirmwareManufacturer) == 0 || evt.FirmwareManufacturerStr.Data == opts.FirmwareManufacturer {
				return exel.Locate(evt.RIMLocatorType, evt.RIMLocator.Data, locopts)
			}
		}
	}
	return nil, fmt.Errorf("matching sp800155 firmware manufacturer %v not found", opts.FirmwareManufacturer)
}

func fromSevSnpAttestationProto(at *spb.Attestation) ([]byte, string, error) {
	if out, err := extractsev.FromAttestation(at); err == nil {
		return out, "", nil
	}
	meas := at.GetReport().GetMeasurement()
	return nil, extractsev.GCETcbObjectName(sev.GCEUefiFamilyID, meas), nil
}

func fromTdxAttestationProto(at *tpb.QuoteV4) string {
	return extracttdx.GCETcbObjectName(at.GetTdQuoteBody().GetMrTd())
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

	tdx := &tpb.QuoteV4{}
	if err := proto.Unmarshal(quote, tdx); err == nil {
		tpmat.TeeAttestation = &tpmpb.Attestation_TdxAttestation{TdxAttestation: tdx}
		return tpmat, nil
	}

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

	// Attempt to decode as a raw TDX quote.
	if tdxquote, err := tabi.QuoteToProto(quote); err == nil {
		switch tq := tdxquote.(type) {
		case *tpb.QuoteV4:
			tpmat.TeeAttestation = &tpmpb.Attestation_TdxAttestation{TdxAttestation: tq}
			return tpmat, nil
		default:
			return nil, fmt.Errorf("unknown TDX attestation format %T", tdxquote)
		}
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
	case *tpmpb.Attestation_TdxAttestation:
		return nil, fromTdxAttestationProto(at.TdxAttestation), nil
	}
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
	// First try the event logger.
	if opts.EventLogLocation != "" && !opts.ForceFetch {
		out, evErr = opts.fromEventLog()
		if evErr == nil {
			return out, nil
		}
	}

	// If the verbatim quote is provided, try that next.
	endorsement, objectName, quoteErr = opts.fromQuote(opts.Quote)
	if quoteErr == nil && len(endorsement) > 0 && !opts.ForceFetch {
		return endorsement, nil
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
		if len(endorsement) > 0 && !opts.ForceFetch {
			return endorsement, nil
		}
	}

	// Then try the internet.
	if opts.Getter == nil {
		internetErr = ErrGetterNil
	} else {
		endorsement, internetErr = opts.Getter.Get(verify.GCETcbURL(objectName))
		if internetErr == nil {
			return endorsement, nil
		}
	}
	return nil, multierr.Combine(evErr, quoteErr, internetErr)
}
