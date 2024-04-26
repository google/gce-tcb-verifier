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

package gcetcbendorsement

import (
	"context"
	"testing"

	testlib "github.com/google/gce-tcb-verifier/gcetcbendorsement/testing"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/go-cmp/cmp"
	cpb "github.com/google/go-sev-guest/proto/check"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestSevPolicy(t *testing.T) {
	ctx := context.Background()
	tcs := []struct {
		name        string
		endorsement *epb.VMLaunchEndorsement
		opts        *SevPolicyOptions
		want        *cpb.Policy
		wantErr     string
	}{
		{
			name:    "need sev_snp",
			opts:    &SevPolicyOptions{},
			wantErr: "does not contain sev_snp",
		},
		{
			name: "need launch_vmsas",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{Policy: 458752},
				})},
			opts:    &SevPolicyOptions{},
			wantErr: "launch_vmsas must be set to modify policy",
		},
		{
			name: "launch_vmsas and no measurement",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{Policy: 458752},
				})},
			opts:    &SevPolicyOptions{LaunchVmsas: 1},
			wantErr: "failed to find measurement for 1 VMSA",
		},
		{
			name: "measurement only",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{
						Policy:       458752,
						Measurements: map[uint32][]byte{1: []byte("meas")},
					},
				})},
			opts: &SevPolicyOptions{LaunchVmsas: 1},
			want: &cpb.Policy{
				Policy:         458752,
				MinimumVersion: "0.0",
				Measurement:    []byte("meas")},
		},
		{
			name: "measurement conflict",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{
						Measurements: map[uint32][]byte{1: []byte("meas")},
					},
				})},
			opts: &SevPolicyOptions{
				LaunchVmsas: 1,
				Base:        &cpb.Policy{Measurement: []byte("not meas")},
			},
			wantErr: "measurement [110 111 116 32 109 101 97 115] overwritten with [109 101 97 115]",
		},
		{
			name: "measurement overwrite",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{
						Measurements: map[uint32][]byte{1: []byte("meas")},
					},
				})},
			opts: &SevPolicyOptions{
				LaunchVmsas: 1,
				Base:        &cpb.Policy{Measurement: []byte("not meas")},
				Overwrite:   true,
			},
			want: &cpb.Policy{Measurement: []byte("meas")},
		},
		{
			name: "svn conflict",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{
						Svn: 2,
					},
				})},
			opts: &SevPolicyOptions{
				LaunchVmsas: 1,
				Base:        &cpb.Policy{MinimumGuestSvn: 3},
			},
			wantErr: "minimum_guest_svn 3 rejects 2",
		},
		{
			name: "svn non-conflict",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{
						Svn:          2,
						Measurements: map[uint32][]byte{1: []byte("meas")},
					},
				})},
			opts: &SevPolicyOptions{
				LaunchVmsas: 1,
				Base:        &cpb.Policy{MinimumGuestSvn: 1},
			},
			want: &cpb.Policy{MinimumGuestSvn: 1, Measurement: []byte("meas")},
		},
		{
			name: "svn overwrite",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{
						Svn:          2,
						Measurements: map[uint32][]byte{1: []byte("meas")},
					},
				})},
			opts: &SevPolicyOptions{
				LaunchVmsas: 1,
				Base:        &cpb.Policy{MinimumGuestSvn: 3},
				Overwrite:   true,
			},
			want: &cpb.Policy{MinimumGuestSvn: 2, Measurement: []byte("meas")},
		},
		{
			name: "policy conflict",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{
						Policy: 4,
					},
				})},
			opts: &SevPolicyOptions{
				LaunchVmsas: 1,
				Base:        &cpb.Policy{Policy: 5},
			},
			wantErr: "policy 5 overwritten with 4",
		},
		{
			name: "policy overwrite",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{
						Policy:       4,
						Measurements: map[uint32][]byte{1: []byte("meas")},
					},
				})},
			opts: &SevPolicyOptions{
				LaunchVmsas: 1,
				Base:        &cpb.Policy{Policy: 5},
				Overwrite:   true,
			},
			want: &cpb.Policy{Policy: 4, Measurement: []byte("meas")},
		},
		{
			name: "id key bad cert",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{
						CaBundle:     []byte("bad cert"),
						Measurements: map[uint32][]byte{1: []byte("meas")},
					},
				})},
			opts: &SevPolicyOptions{
				LaunchVmsas: 1,
				Base:        &cpb.Policy{},
			},
			wantErr: "could not parse CA bundle as PEM",
		},
		{
			name: "id key bad type",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{
						CaBundle:     []byte("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"),
						Measurements: map[uint32][]byte{1: []byte("meas")},
					},
				})},
			opts: &SevPolicyOptions{
				LaunchVmsas: 1,
				Base:        &cpb.Policy{},
			},
			wantErr: "ca bundle identity key PEM type is \"PUBLIC KEY\", want CERTIFICATE",
		},
		{
			name: "id key extend",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{
						CaBundle:     []byte("-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----\n"),
						Measurements: map[uint32][]byte{1: []byte("meas")},
					},
				})},
			opts: &SevPolicyOptions{
				LaunchVmsas: 1,
				Base:        &cpb.Policy{TrustedIdKeys: [][]byte{[]byte("begin")}},
			},
			want: &cpb.Policy{
				TrustedIdKeys: [][]byte{[]byte("begin"), []byte("cert")},
				Measurement:   []byte("meas")},
		},

		{
			name: "author key bad cert",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{
						CaBundle:     []byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\nbad cert"),
						Measurements: map[uint32][]byte{1: []byte("meas")},
					},
				})},
			opts: &SevPolicyOptions{
				LaunchVmsas: 1,
				Base:        &cpb.Policy{},
			},
			wantErr: "could not parse CA bundle remainder as PEM",
		},
		{
			name: "author key bad type",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{
						CaBundle:     []byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"),
						Measurements: map[uint32][]byte{1: []byte("meas")},
					},
				})},
			opts: &SevPolicyOptions{
				LaunchVmsas: 1,
				Base:        &cpb.Policy{},
			},
			wantErr: "ca bundle author key PEM type is \"PUBLIC KEY\", want CERTIFICATE",
		},
		{
			name: "author key extend",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{
						CaBundle:     []byte("-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nc2tpcnQ=\n-----END CERTIFICATE-----\n"),
						Measurements: map[uint32][]byte{1: []byte("meas")},
					},
				})},
			opts: &SevPolicyOptions{
				LaunchVmsas: 1,
				Base: &cpb.Policy{
					TrustedIdKeys:     [][]byte{[]byte("begin")},
					TrustedAuthorKeys: [][]byte{[]byte("bagin")},
				},
			},
			want: &cpb.Policy{
				TrustedIdKeys:     [][]byte{[]byte("begin"), []byte("cert")},
				TrustedAuthorKeys: [][]byte{[]byte("bagin"), []byte("skirt")},
				Measurement:       []byte("meas")},
		},
		{
			name: "unspecified launch_vmsas",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{Policy: 458752, Svn: 5},
				})},
			opts: &SevPolicyOptions{AllowUnspecifiedVmsas: true},
			want: &cpb.Policy{Policy: 458752, MinimumVersion: "0.0"},
		},
		{
			name: "unspecified launch_vmsas overwrite",
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, &epb.VMGoldenMeasurement{
					SevSnp: &epb.VMSevSnp{Policy: 458752, Svn: 5},
				})},
			opts: &SevPolicyOptions{AllowUnspecifiedVmsas: true, Overwrite: true},
			want: &cpb.Policy{Policy: 458752, MinimumVersion: "0.0", MinimumGuestSvn: 5},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SevPolicy(ctx, tc.endorsement, tc.opts)
			if !match.Error(err, tc.wantErr) {
				t.Fatalf("SevPolicy(_, %v, %v) = _, %v errored unexpectedly. Want %q", tc.endorsement,
					tc.opts, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if diff := cmp.Diff(got, tc.want, protocmp.Transform()); diff != "" {
				t.Errorf("SevPolicy(_, %v, %v) returned diff (-want +got):\n%s", tc.endorsement, tc.opts,
					diff)
			}
		})
	}
}
