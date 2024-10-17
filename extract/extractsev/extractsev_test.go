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

package extractsev

import (
	"testing"

	"github.com/google/gce-tcb-verifier/sev"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/uuid"
)

func TestFromAttestation(t *testing.T) {
	tests := []struct {
		name    string
		at      *spb.Attestation
		want    []byte
		wantErr string
	}{
		{
			name: "happy path",
			at: &spb.Attestation{CertificateChain: &spb.CertificateChain{Extras: map[string][]byte{
				sev.GCEFwCertGUID: []byte("found"),
			}}},
			want: []byte("found"),
		},
		{
			name:    "attestation nil",
			wantErr: ErrNotInExtras.Error(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FromAttestation(tc.at)
			if !match.Error(err, tc.wantErr) {
				t.Fatalf("FromAttestation(%v) = %v errored unexpectedly. Want %q", tc.at, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("FromAttestation(%v) returned an unexpected diff (-want +got): %v", tc.at, diff)
			}
		})
	}
}

func TestFromCertTable(t *testing.T) {
	fwGUID := uuid.MustParse(sev.GCEFwCertGUID)
	tests := []struct {
		name    string
		table   []byte
		want    []byte
		wantErr string
	}{
		{
			name: "happy path",
			table: (&abi.CertTable{
				Entries: []abi.CertTableEntry{
					{
						GUID:    fwGUID,
						RawCert: []byte("found"),
					},
				},
			}).Marshal(),
			want: []byte("found"),
		},
		{
			name:    "empty table",
			wantErr: "cert not found for GUID 9f4116cd-c503-4f5a-8f6f-fb68882f4ce2",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FromCertTable(tc.table)
			if !match.Error(err, tc.wantErr) {
				t.Fatalf("FromCertTable(%v) = %v errored unexpectedly. Want %q", tc.table, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("FromCertTable(%v) returned an unexpected diff (-want +got): %v", tc.table, diff)
			}
		})
	}
}

func TestGCETcbObjectName(t *testing.T) {
	tcs := []struct {
		name        string
		familyID    string
		measurement []byte
		want        string
	}{
		{
			name:        "ovmf",
			familyID:    sev.GCEUefiFamilyID,
			measurement: []byte{3, 1, 2},
			want:        "ovmf_x64_csm/sevsnp/030102.binarypb",
		},
		{
			name:        "auxblob GUID",
			familyID:    sev.GCEFwCertGUID,
			measurement: []byte{3, 1, 2},
			want:        "ovmf_x64_csm/sevsnp/030102.binarypb",
		},
		{
			name:        "unknown",
			familyID:    "not even a guid",
			measurement: []byte{3, 1, 2},
			want:        "unknown/sevsnp/030102.binarypb",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := GCETcbObjectName(tc.familyID, tc.measurement)
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Fatalf("GCETcbObjectName(%v, %v) returned an unexpected diff (-got +want): %v",
					tc.familyID, tc.measurement, diff)
			}
		})
	}
}
