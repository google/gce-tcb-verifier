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
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	testlib "github.com/google/gce-tcb-verifier/gcetcbendorsement/testing"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/gce-tcb-verifier/sev"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/testing/protocmp"
	fmpb "google.golang.org/protobuf/types/known/fieldmaskpb"
	tpb "google.golang.org/protobuf/types/known/timestamppb"
)

func testGolden() *epb.VMGoldenMeasurement {
	family := uuid.MustParse(sev.GCEUefiFamilyID)
	return &epb.VMGoldenMeasurement{
		Timestamp: &tpb.Timestamp{Seconds: 4, Nanos: 5},
		Commit:    []byte("commit"),
		SevSnp: &epb.VMSevSnp{
			Svn: 45,
			Measurements: map[uint32][]byte{
				1: []byte("measurement1"),
				2: []byte{3, 1, 2},
			},
			FamilyId: family[:],
		},
	}
}

func TestMask(t *testing.T) {
	gm := testGolden()
	defaultOpts := func(form BytesForm) *MaskOptions {
		return &MaskOptions{
			BytesForm: form,
			PathRenderer: map[string]FieldRenderer{
				"timestamp": RenderTimestamp(time.RFC3339),
			},
			Writer: NonterminalWriter{bytes.NewBufferString("")},
		}
	}
	badOpts := func(form BytesForm) *MaskOptions {
		return &MaskOptions{BytesForm: form, Writer: NonterminalWriter{testlib.FailWriter{}}}
	}
	tcs := []struct {
		name    string
		mask    *fmpb.FieldMask
		opts    *MaskOptions
		wantErr string
		want    []string // any of these
		cmpopts []cmp.Option
	}{
		{
			name: "timestamp and map key",
			mask: &fmpb.FieldMask{Paths: []string{"timestamp", "sev_snp.measurements[2]"}},
			want: []string{"1970-01-01T00:00:04Z\n030102"},
			opts: defaultOpts(BytesHex),
		},
		{
			name: "map entries",
			mask: &fmpb.FieldMask{Paths: []string{"sev_snp.measurements"}},
			want: []string{"1: [109 101 97 115 117 114 101 109 101 110 116 49]\n2: [3 1 2]",
				"2: [3 1 2]\n1: [109 101 97 115 117 114 101 109 101 110 116 49]"},
			opts: defaultOpts(BytesHex),
		},
		{
			name: "map key raw",
			mask: &fmpb.FieldMask{Paths: []string{"sev_snp.measurements[1]"}},
			want: []string{"measurement1"},
			opts: defaultOpts(BytesRaw),
		},
		{
			name: "guid",
			mask: &fmpb.FieldMask{Paths: []string{"sev_snp.family_id"}},
			want: []string{"f73a6949-e8f3-473b-9553-e40e056fa3a2"},
			opts: defaultOpts(BytesHexGuidify),
		},
		{
			name: "non-guid hex",
			mask: &fmpb.FieldMask{Paths: []string{"commit"}},
			want: []string{"636f6d6d6974"},
			opts: defaultOpts(BytesHexGuidify),
		},
		{
			name:    "bad guid",
			mask:    &fmpb.FieldMask{Paths: []string{"sev_snp.family_id"}},
			wantErr: "nope",
			opts:    badOpts(BytesHexGuidify),
		},
		{
			name: "uint",
			mask: &fmpb.FieldMask{Paths: []string{"sev_snp.svn"}},
			want: []string{"45"},
			opts: defaultOpts(BytesRaw),
		},
		{
			name: "message",
			mask: &fmpb.FieldMask{Paths: []string{"sev_snp"}},
			want: []string{`svn:  45
measurements:  {
  key: 1
  value: "measurement1"
}
measurements: {
  key: 2
  value: "\x03\x01\x02"
}
family_id: "\xf7:iI\xe8\xf3G;\x95S\xe4\x0e\x05o\xa3\xa2"`},
			cmpopts: []cmp.Option{cmp.Comparer(func(a, b string) bool {
				vma := &epb.VMSevSnp{}
				vmb := &epb.VMSevSnp{}
				if err := prototext.Unmarshal([]byte(a), vma); err != nil {
					return false
				}
				if err := prototext.Unmarshal([]byte(b), vmb); err != nil {
					return false
				}
				return cmp.Equal(vma, vmb, protocmp.Transform())
			})},
			opts: defaultOpts(BytesRaw),
		},
		{
			name:    "bad path",
			mask:    &fmpb.FieldMask{Paths: []string{"bad_path"}},
			wantErr: "error in parsing path \"bad_path\"",
			opts:    defaultOpts(BytesHex),
		},
		{
			name:    "no mask",
			wantErr: "mask is nil",
			opts:    defaultOpts(BytesHex),
		},
		{
			name: "base64",
			mask: &fmpb.FieldMask{Paths: []string{"commit"}},
			opts: defaultOpts(BytesBase64),
			want: []string{"Y29tbWl0"},
		},
		{
			name:    "bad base64",
			mask:    &fmpb.FieldMask{Paths: []string{"commit"}},
			opts:    badOpts(BytesBase64),
			wantErr: "nope",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.opts.Mask(gm, tc.mask); !match.Error(err, tc.wantErr) {
				t.Fatalf("%v.Mask(_, %v) failed unexpectedly. Got %v. Want %q", tc.opts, tc.mask, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			got := tc.opts.Writer.(NonterminalWriter).Writer.(*bytes.Buffer).String()
			var found bool
			var diffs []string
			for _, want := range tc.want {
				diff := cmp.Diff(got, want, tc.cmpopts...)
				if diff != "" {
					diffs = append(diffs, diff)
				} else {
					found = true
					break
				}
			}
			if !found {
				var quoted []string
				for _, w := range tc.want {
					quoted = append(quoted, fmt.Sprintf("%q", w))
				}
				t.Fatalf("%v.Mask(_, %v) = %q. Want one of %s.\nDiffs (-got, +want): %s", tc.opts, tc.mask,
					got,
					strings.Join(quoted, ", "),
					strings.Join(diffs, "\n"))
			}
		})
	}
}

func TestBadRender(t *testing.T) {
	tcs := []struct {
		name  string
		field string
		want  string
	}{
		{
			name:  "bad timestamp for non-message",
			field: "commit",
			want:  "unexpected type []uint8. Want protoreflect.Message",
		},
		{
			name:  "bad timestamp for message",
			field: "sev_snp",
			want:  "Want *tpb.Timestamp",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			opts := &MaskOptions{
				BytesForm: BytesRaw,
				PathRenderer: map[string]FieldRenderer{
					tc.field: RenderTimestamp(time.RFC3339),
				},
				Writer: NonterminalWriter{bytes.NewBufferString("")},
			}
			if err := opts.Mask(testGolden(), &fmpb.FieldMask{Paths: []string{tc.field}}); !match.Error(err, tc.want) {
				t.Fatalf("{badRenderTimestamp}.Mask(...) = %v. Want %q", err, tc.want)
			}
		})
	}
}
