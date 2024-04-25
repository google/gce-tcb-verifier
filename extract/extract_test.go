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

package extract

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/gce-tcb-verifier/sev"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/go-sev-guest/abi"
	test "github.com/google/go-sev-guest/testing"
	tpmpb "github.com/google/go-tpm-tools/proto/attest"
	"google.golang.org/protobuf/proto"
)

func TestExtractEndorsement(t *testing.T) {
	now := time.Now()
	sa, err := test.DefaultTestOnlyCertChain("Milan", now)
	if err != nil {
		t.Fatalf("test.DefaultTestOnlyCertChain('Milan', %v) = _, %v, want nil", now, err)
	}
	b := &test.AmdSignerBuilder{
		Extras: map[string][]byte{
			sev.GCEFwCertGUID: []byte("ding ding"),
		},
	}
	sb, err := b.TestOnlyCertChain()
	if err != nil {
		t.Fatalf("b.TestOnlyCertChain() = _, %v, want nil", err)
	}
	nilqp, err := test.TcQuoteProvider(nil, &test.DeviceOptions{})
	if err != nil {
		t.Fatalf("test.TcQuoteProvider(nil, {}) = _, %v, want nil", err)
	}
	noextraqp, err := test.TcQuoteProvider(test.TestCases(), &test.DeviceOptions{Signer: sa})
	if err != nil {
		t.Fatalf("test.TcQuoteProvider(tcs, noextras) = _, %v, want nil", err)
	}
	xtraqp, err := test.TcQuoteProvider(test.TestCases(), &test.DeviceOptions{Signer: sb})
	if err != nil {
		t.Fatalf("test.TcQuoteProvider(tcs, xtras) = _, %v, want nil", err)
	}
	var zeroes [abi.ReportDataSize]byte
	goodQuote, err := xtraqp.GetRawQuote(zeroes)
	if err != nil {
		t.Fatalf("xtraqp.GetRawQuote() = _, %v, want nil", err)
	}
	snpProto, err := abi.ReportCertsToProto(goodQuote)
	if err != nil {
		t.Fatalf("abi.ReportCertsToProto() = _, %v, want nil", err)
	}
	tpmAttestation, err := proto.Marshal(&tpmpb.Attestation{
		TeeAttestation: &tpmpb.Attestation_SevSnpAttestation{SevSnpAttestation: snpProto},
	})
	if err != nil {
		t.Fatalf("proto.Marshal(tpm.Attestation{...}) = _, %v, want nil", err)
	}
	goodAttestation, err := proto.Marshal(snpProto)
	if err != nil {
		t.Fatalf("proto.Marshal(snpProto) = _, %v, want nil", err)
	}
	goodReport, err := proto.Marshal(snpProto.GetReport())
	if err != nil {
		t.Fatalf("proto.Marshal(snpProto.GetReport()) = _, %v, want nil", err)
	}

	goodGetter := &test.Getter{
		Responses: map[string][]test.GetResponse{
			"https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/sevsnp/000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000.binarypb": {{Body: []byte("ding ding")}},
		},
	}
	tcs := []struct {
		name    string
		opts    *Options
		want    []byte
		wantErr string
	}{
		{name: "no options", wantErr: ErrOptionsNil.Error()},
		{name: "no provider", opts: &Options{}, wantErr: ErrGetterNil.Error()},
		{
			name: "quote failure",
			opts: &Options{
				Provider: nilqp,
			},
			wantErr: "no response", // error when no test case defines the report for the nonce.
		},
		{
			name: "success from provider",
			opts: &Options{
				Provider: xtraqp,
			},
			want: []byte("ding ding"),
		},
		{
			name: "bad quote format",
			opts: &Options{
				Quote: []byte("bad quote format"),
			},
			wantErr: ErrUnknownFormat.Error(),
		},
		{
			name: "given raw quote",
			opts: &Options{
				Quote: goodQuote,
			},
			want: []byte("ding ding"),
		},
		{
			name: "given serialized report",
			opts: &Options{
				Quote:  goodReport,
				Getter: goodGetter,
			},
			want: []byte("ding ding"),
		},
		{
			name: "given serialized snp attestation",
			opts: &Options{
				Quote: goodAttestation,
			},
			want: []byte("ding ding"),
		},
		{
			name: "just certs",
			opts: &Options{
				Quote: goodQuote[abi.ReportSize:],
			},
			want: []byte("ding ding"),
		},
		{
			name: "tpm tools attestation",
			opts: &Options{Quote: tpmAttestation},
			want: []byte("ding ding"),
		},
		{
			name: "success from get",
			opts: &Options{
				Provider: noextraqp,
				Getter:   goodGetter,
			},
			want: []byte("ding ding"),
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Endorsement(tc.opts)
			if !match.Error(err, tc.wantErr) {
				t.Fatalf("Endorsement(%v) = _, %v, want %v", tc.opts, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("Endorsement(%v) = %v, nil, want %v", tc.opts, got, tc.want)
			}
		})
	}
}
